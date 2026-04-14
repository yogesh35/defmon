"""Tests for DefMon SOAR PlaybookEngine (soar/playbooks.py).

Covers:
- Critical severity: all 4 actions dispatched
- High severity: block_ip + create_incident + send_alert_notification
- Medium severity: create_incident + send_alert_notification
- Low severity: create_incident only
- Fault tolerance: one action fails, others continue
- Unknown severity: no actions dispatched
- lock_account skipped when no username present
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from defmon.detection.engine import Alert
from defmon.models import Incident, IncidentStatus, SeverityLevel
from defmon.soar.playbooks import PlaybookEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def mock_settings():
    """Create mock settings with playbook config."""
    settings = MagicMock()
    settings.soar_config = {
        "use_system_block": False,
        "playbooks": {
            "Critical": [
                "block_ip",
                "lock_account",
                "create_incident",
                "send_alert_notification",
            ],
            "High": [
                "block_ip",
                "create_incident",
                "send_alert_notification",
            ],
            "Medium": [
                "create_incident",
                "send_alert_notification",
            ],
            "Low": [
                "create_incident",
            ],
        },
    }
    return settings


@pytest.fixture
def engine(mock_settings):
    """Create a PlaybookEngine with mock settings."""
    return PlaybookEngine(settings=mock_settings)


@pytest.fixture
def mock_session():
    """Create a mock async database session."""
    session = AsyncMock()
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.execute = AsyncMock()
    session.commit = AsyncMock()
    return session


@pytest.fixture
def critical_alert():
    """Critical severity alert with username."""
    return Alert(
        alert_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        ip="192.168.1.200",
        rule_id="SQLI_001",
        severity="Critical",
        description="SQL Injection attempt detected",
        raw_event='GET /search?q=1\' OR 1=1--',
        risk_score=65.0,
        tags=["botnet"],
        username="admin",
    )


@pytest.fixture
def high_alert():
    """High severity alert."""
    return Alert(
        alert_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        ip="10.10.10.10",
        rule_id="XSS_001",
        severity="High",
        description="XSS attempt detected",
        raw_event='GET /comment?text=<script>alert(1)</script>',
        risk_score=50.0,
    )


@pytest.fixture
def medium_alert():
    """Medium severity alert."""
    return Alert(
        alert_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        ip="172.16.0.50",
        rule_id="SCAN_001",
        severity="Medium",
        description="Port scanning detected",
        raw_event='GET /nonexistent HTTP/1.1',
        risk_score=30.0,
    )


@pytest.fixture
def low_alert():
    """Low severity alert."""
    return Alert(
        alert_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        ip="10.0.0.5",
        rule_id="INFO_001",
        severity="Low",
        description="Informational event",
        raw_event='GET /robots.txt HTTP/1.1',
        risk_score=10.0,
    )


@pytest.fixture
def mock_incident():
    """Create a mock Incident object."""
    return Incident(
        case_id=uuid.uuid4(),
        alert_id=uuid.uuid4(),
        status=IncidentStatus.OPEN,
        severity=SeverityLevel.CRITICAL,
        description="Test incident",
    )


# ---------------------------------------------------------------------------
# Test: Critical Severity — All 4 Actions
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_critical_playbook(engine, critical_alert, mock_session, mock_incident):
    """Critical alert should trigger all 4 actions."""
    with patch("defmon.soar.playbooks.block_ip", new_callable=AsyncMock) as mock_block, \
         patch("defmon.soar.playbooks.lock_account", new_callable=AsyncMock) as mock_lock, \
         patch("defmon.soar.playbooks.create_incident", new_callable=AsyncMock) as mock_create, \
         patch("defmon.soar.playbooks.send_alert_notification", new_callable=AsyncMock) as mock_send:

        mock_create.return_value = mock_incident

        result = await engine.execute(critical_alert, mock_session)

    assert result["severity"] == "Critical"
    assert len(result["actions_succeeded"]) == 4
    assert len(result["actions_failed"]) == 0
    assert result["incident"] is mock_incident

    mock_block.assert_called_once()
    mock_lock.assert_called_once_with(username="admin", session=mock_session)
    mock_create.assert_called_once()
    mock_send.assert_called_once()


# ---------------------------------------------------------------------------
# Test: High Severity — 3 Actions (no lock_account)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_high_playbook(engine, high_alert, mock_session, mock_incident):
    """High alert should trigger block_ip, create_incident, send_notification."""
    with patch("defmon.soar.playbooks.block_ip", new_callable=AsyncMock) as mock_block, \
         patch("defmon.soar.playbooks.lock_account", new_callable=AsyncMock) as mock_lock, \
         patch("defmon.soar.playbooks.create_incident", new_callable=AsyncMock) as mock_create, \
         patch("defmon.soar.playbooks.send_alert_notification", new_callable=AsyncMock) as mock_send:

        mock_create.return_value = mock_incident

        result = await engine.execute(high_alert, mock_session)

    assert result["severity"] == "High"
    assert len(result["actions_succeeded"]) == 3
    assert "block_ip" in result["actions_succeeded"]
    assert "create_incident" in result["actions_succeeded"]
    assert "send_alert_notification" in result["actions_succeeded"]

    mock_block.assert_called_once()
    mock_lock.assert_not_called()  # Not in High playbook
    mock_create.assert_called_once()
    mock_send.assert_called_once()


# ---------------------------------------------------------------------------
# Test: Medium Severity — 2 Actions
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_medium_playbook(engine, medium_alert, mock_session, mock_incident):
    """Medium alert should trigger create_incident + send_notification only."""
    with patch("defmon.soar.playbooks.block_ip", new_callable=AsyncMock) as mock_block, \
         patch("defmon.soar.playbooks.create_incident", new_callable=AsyncMock) as mock_create, \
         patch("defmon.soar.playbooks.send_alert_notification", new_callable=AsyncMock) as mock_send:

        mock_create.return_value = mock_incident

        result = await engine.execute(medium_alert, mock_session)

    assert result["severity"] == "Medium"
    assert len(result["actions_succeeded"]) == 2
    assert "create_incident" in result["actions_succeeded"]
    assert "send_alert_notification" in result["actions_succeeded"]

    mock_block.assert_not_called()
    mock_create.assert_called_once()
    mock_send.assert_called_once()


# ---------------------------------------------------------------------------
# Test: Low Severity — 1 Action
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_low_playbook(engine, low_alert, mock_session, mock_incident):
    """Low alert should trigger only create_incident."""
    with patch("defmon.soar.playbooks.block_ip", new_callable=AsyncMock) as mock_block, \
         patch("defmon.soar.playbooks.create_incident", new_callable=AsyncMock) as mock_create, \
         patch("defmon.soar.playbooks.send_alert_notification", new_callable=AsyncMock) as mock_send:

        mock_create.return_value = mock_incident

        result = await engine.execute(low_alert, mock_session)

    assert result["severity"] == "Low"
    assert len(result["actions_succeeded"]) == 1
    assert "create_incident" in result["actions_succeeded"]

    mock_block.assert_not_called()
    mock_send.assert_not_called()
    mock_create.assert_called_once()


# ---------------------------------------------------------------------------
# Test: Fault Tolerance — One Action Fails
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_fault_tolerance(engine, critical_alert, mock_session, mock_incident):
    """If one action fails, remaining actions should still execute."""
    with patch("defmon.soar.playbooks.block_ip", new_callable=AsyncMock) as mock_block, \
         patch("defmon.soar.playbooks.lock_account", new_callable=AsyncMock) as mock_lock, \
         patch("defmon.soar.playbooks.create_incident", new_callable=AsyncMock) as mock_create, \
         patch("defmon.soar.playbooks.send_alert_notification", new_callable=AsyncMock) as mock_send:

        # Make block_ip raise an exception
        mock_block.side_effect = Exception("Database connection failed")
        mock_create.return_value = mock_incident

        result = await engine.execute(critical_alert, mock_session)

    # block_ip failed, but the other 3 should succeed
    assert len(result["actions_succeeded"]) == 3
    assert len(result["actions_failed"]) == 1
    assert result["actions_failed"][0]["action"] == "block_ip"
    assert "Database connection failed" in result["actions_failed"][0]["error"]

    # Other actions still called
    mock_lock.assert_called_once()
    mock_create.assert_called_once()
    mock_send.assert_called_once()


# ---------------------------------------------------------------------------
# Test: Multiple Failures — Engine Continues
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_multiple_failures_continue(engine, critical_alert, mock_session):
    """Multiple failures should all be logged, engine keeps running."""
    with patch("defmon.soar.playbooks.block_ip", new_callable=AsyncMock) as mock_block, \
         patch("defmon.soar.playbooks.lock_account", new_callable=AsyncMock) as mock_lock, \
         patch("defmon.soar.playbooks.create_incident", new_callable=AsyncMock) as mock_create, \
         patch("defmon.soar.playbooks.send_alert_notification", new_callable=AsyncMock) as mock_send:

        mock_block.side_effect = Exception("Block failed")
        mock_lock.side_effect = Exception("Lock failed")
        mock_create.return_value = Incident(
            case_id=uuid.uuid4(), alert_id=uuid.uuid4(),
            status=IncidentStatus.OPEN, severity=SeverityLevel.CRITICAL,
        )

        result = await engine.execute(critical_alert, mock_session)

    assert len(result["actions_failed"]) == 2
    assert len(result["actions_succeeded"]) == 2


# ---------------------------------------------------------------------------
# Test: Unknown Severity — No Actions
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_unknown_severity(engine, mock_session):
    """Alert with unrecognized severity should dispatch no actions."""
    unknown_alert = Alert(
        alert_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        ip="1.2.3.4",
        rule_id="UNKNOWN",
        severity="DEBUG",
        description="Debug event",
        raw_event="test",
        risk_score=0.0,
    )

    result = await engine.execute(unknown_alert, mock_session)

    assert result["severity"] == "DEBUG"
    assert len(result["actions_attempted"]) == 0
    assert len(result["actions_succeeded"]) == 0
    assert result["incident"] is None


# ---------------------------------------------------------------------------
# Test: lock_account Skipped Without Username
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_lock_account_skipped_no_username(engine, mock_session, mock_incident):
    """lock_account in Critical playbook should be skipped if no username."""
    alert_no_user = Alert(
        alert_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        ip="192.168.1.100",
        rule_id="SQLI_001",
        severity="Critical",
        description="SQL Injection",
        raw_event="test",
        risk_score=60.0,
        username=None,  # No username
    )

    with patch("defmon.soar.playbooks.block_ip", new_callable=AsyncMock), \
         patch("defmon.soar.playbooks.lock_account", new_callable=AsyncMock) as mock_lock, \
         patch("defmon.soar.playbooks.create_incident", new_callable=AsyncMock) as mock_create, \
         patch("defmon.soar.playbooks.send_alert_notification", new_callable=AsyncMock):

        mock_create.return_value = mock_incident
        result = await engine.execute(alert_no_user, mock_session)

    # lock_account action is in the list but dispatched with no-op
    assert len(result["actions_succeeded"]) == 4  # All succeed (lock_account skips gracefully)
    mock_lock.assert_not_called()  # lock_account not actually called since no username


# ---------------------------------------------------------------------------
# Test: PlaybookEngine Initialization
# ---------------------------------------------------------------------------
def test_playbook_engine_init(mock_settings):
    """PlaybookEngine should load playbooks from config."""
    engine = PlaybookEngine(settings=mock_settings)
    assert len(engine._playbooks) == 4
    assert "Critical" in engine._playbooks
    assert "High" in engine._playbooks
    assert "Medium" in engine._playbooks
    assert "Low" in engine._playbooks
