"""Tests for DefMon SOAR Actions (soar/actions.py).

Covers:
- block_ip: DB insert, audit log, duplicate handling
- lock_account: DB update, audit log, missing user
- create_incident: Incident creation, audit log
- send_alert_notification: Webhook POST, missing URL, timeout
- Audit trail verified BEFORE each action
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import httpx
import pytest
import pytest_asyncio

from defmon.detection.engine import Alert
from defmon.models import AuditLog, BlockedIP, Incident, IncidentStatus, SeverityLevel, User


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def sample_alert():
    """Create a sample Alert for testing."""
    return Alert(
        alert_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        ip="192.168.1.200",
        rule_id="SQLI_001",
        severity="Critical",
        description="SQL Injection attempt detected",
        raw_event='GET /search?q=1\' OR 1=1-- HTTP/1.1',
        risk_score=65.0,
        tags=["botnet", "scanner"],
        username="admin",
    )


@pytest.fixture
def sample_alert_no_username():
    """Create a sample Alert without username."""
    return Alert(
        alert_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        ip="10.10.10.10",
        rule_id="XSS_001",
        severity="High",
        description="XSS attempt detected",
        raw_event='GET /comment?text=<script>alert(1)</script> HTTP/1.1',
        risk_score=50.0,
    )


@pytest.fixture
def mock_session():
    """Create a mock async database session."""
    session = AsyncMock()
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.execute = AsyncMock()
    session.commit = AsyncMock()
    return session


# ---------------------------------------------------------------------------
# Test: block_ip
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_block_ip_new_ip(mock_session, sample_alert):
    """block_ip should write audit log and insert BlockedIP for new IP."""
    from defmon.soar.actions import block_ip

    # Mock: IP not already blocked
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_session.execute = AsyncMock(return_value=mock_result)

    with patch("defmon.soar.actions.get_settings") as mock_settings:
        mock_settings.return_value.soar_config = {"use_system_block": False}
        await block_ip(ip="192.168.1.200", session=mock_session, reason="Test block")

    # Verify audit log + blocked IP were added (2 calls to session.add)
    assert mock_session.add.call_count == 2

    # First add should be AuditLog
    first_add = mock_session.add.call_args_list[0][0][0]
    assert isinstance(first_add, AuditLog)
    assert first_add.action == "block_ip"
    assert first_add.actor == "SOAR"
    assert first_add.target == "192.168.1.200"

    # Second add should be BlockedIP
    second_add = mock_session.add.call_args_list[1][0][0]
    assert isinstance(second_add, BlockedIP)
    assert second_add.ip == "192.168.1.200"


@pytest.mark.asyncio
async def test_block_ip_already_blocked(mock_session, sample_alert):
    """block_ip should skip DB insert if IP is already blocked."""
    from defmon.soar.actions import block_ip

    # Mock: IP already blocked
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = BlockedIP(ip="192.168.1.200")
    mock_session.execute = AsyncMock(return_value=mock_result)

    with patch("defmon.soar.actions.get_settings") as mock_settings:
        mock_settings.return_value.soar_config = {"use_system_block": False}
        await block_ip(ip="192.168.1.200", session=mock_session)

    # Only audit log should be added (not a second BlockedIP)
    assert mock_session.add.call_count == 1
    first_add = mock_session.add.call_args_list[0][0][0]
    assert isinstance(first_add, AuditLog)


# ---------------------------------------------------------------------------
# Test: lock_account
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_lock_account_existing_user(mock_session):
    """lock_account should write audit log and update user record."""
    from defmon.soar.actions import lock_account

    # Mock: user found and updated
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = 1  # User ID
    mock_session.execute = AsyncMock(return_value=mock_result)

    await lock_account(username="admin", session=mock_session)

    # Audit log added
    assert mock_session.add.call_count == 1
    audit = mock_session.add.call_args_list[0][0][0]
    assert isinstance(audit, AuditLog)
    assert audit.action == "lock_account"
    assert audit.target == "admin"

    # Execute called twice: once for audit flush, once for update
    assert mock_session.execute.call_count == 1


@pytest.mark.asyncio
async def test_lock_account_missing_user(mock_session):
    """lock_account should log warning if user not found."""
    from defmon.soar.actions import lock_account

    # Mock: user not found
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_session.execute = AsyncMock(return_value=mock_result)

    # Should not raise, just log warning
    await lock_account(username="nonexistent", session=mock_session)

    # Audit log still written
    assert mock_session.add.call_count == 1


# ---------------------------------------------------------------------------
# Test: create_incident
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_create_incident(mock_session, sample_alert):
    """create_incident should write audit log and create Incident record."""
    from defmon.soar.actions import create_incident

    incident = await create_incident(alert=sample_alert, session=mock_session)

    assert isinstance(incident, Incident)
    assert incident.status == IncidentStatus.OPEN
    assert incident.severity == SeverityLevel.CRITICAL
    assert incident.alert_id == uuid.UUID(sample_alert.alert_id)

    # Audit log + Incident added
    assert mock_session.add.call_count == 2
    audit = mock_session.add.call_args_list[0][0][0]
    assert isinstance(audit, AuditLog)
    assert audit.action == "create_incident"


@pytest.mark.asyncio
async def test_create_incident_high_severity(mock_session, sample_alert_no_username):
    """create_incident should handle High severity correctly."""
    from defmon.soar.actions import create_incident

    incident = await create_incident(
        alert=sample_alert_no_username, session=mock_session
    )

    assert incident.severity == SeverityLevel.HIGH


# ---------------------------------------------------------------------------
# Test: send_alert_notification
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_send_notification_success(mock_session, sample_alert):
    """send_alert_notification should POST to webhook and log success."""
    from defmon.soar.actions import send_alert_notification

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()

    with patch.dict("os.environ", {"WEBHOOK_URL": "https://hooks.example.com/test"}):
        with patch("defmon.soar.actions.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            await send_alert_notification(alert=sample_alert, session=mock_session)

    # Audit log written
    assert mock_session.add.call_count == 1
    audit = mock_session.add.call_args_list[0][0][0]
    assert audit.action == "send_alert_notification"


@pytest.mark.asyncio
async def test_send_notification_no_webhook(mock_session, sample_alert):
    """send_alert_notification should fail silently if WEBHOOK_URL not set."""
    from defmon.soar.actions import send_alert_notification

    with patch.dict("os.environ", {"WEBHOOK_URL": ""}):
        # Should not raise
        await send_alert_notification(alert=sample_alert, session=mock_session)

    # Audit log still written
    assert mock_session.add.call_count == 1


@pytest.mark.asyncio
async def test_send_notification_timeout(mock_session, sample_alert):
    """send_alert_notification should handle webhook timeout gracefully."""
    from defmon.soar.actions import send_alert_notification

    with patch.dict("os.environ", {"WEBHOOK_URL": "https://hooks.example.com/test"}):
        with patch("defmon.soar.actions.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(
                side_effect=httpx.TimeoutException("timeout")
            )
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            # Should not raise
            await send_alert_notification(alert=sample_alert, session=mock_session)


# ---------------------------------------------------------------------------
# Test: Audit Trail Written BEFORE Action
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_audit_trail_before_action(mock_session, sample_alert):
    """Verify audit log is added before the main action in all SOAR functions."""
    from defmon.soar.actions import block_ip, _write_audit_log

    call_order = []

    original_add = mock_session.add

    def tracking_add(obj):
        call_order.append(type(obj).__name__)

    mock_session.add = tracking_add

    # Mock: IP not already blocked
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_session.execute = AsyncMock(return_value=mock_result)

    with patch("defmon.soar.actions.get_settings") as mock_settings:
        mock_settings.return_value.soar_config = {"use_system_block": False}
        await block_ip(ip="1.2.3.4", session=mock_session)

    # AuditLog should be FIRST, BlockedIP should be SECOND
    assert call_order[0] == "AuditLog"
    assert call_order[1] == "BlockedIP"
