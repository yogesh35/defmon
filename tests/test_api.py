"""Integration tests for DefMon REST API and Auth (Phase 5)."""

import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI
from sqlalchemy.engine import Result

from defmon.main import app
from defmon.models import User, UserRole, Alert, Incident, IncidentStatus, SeverityLevel
from defmon.api.auth import get_current_user, create_access_token
from defmon.database import get_db

# ---------------------------------------------------------------------------
# Mocks & Fixtures
# ---------------------------------------------------------------------------

mock_user_admin = User(
    id=1, username="admin", role=UserRole.ADMIN, is_active=True, is_locked=False
)
mock_user_analyst = User(
    id=2, username="analyst", role=UserRole.ANALYST, is_active=True, is_locked=False
)
mock_user_viewer = User(
    id=3, username="viewer", role=UserRole.VIEWER, is_active=True, is_locked=False
)


@pytest.fixture
def mock_db_session():
    """Mock async DB session."""
    session = AsyncMock()
    return session


@pytest_asyncio.fixture
async def client_unauth(mock_db_session):
    """AsyncClient without auth."""
    app.dependency_overrides[get_db] = lambda: mock_db_session
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        yield client
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def client_admin(mock_db_session):
    """AsyncClient authed as admin."""
    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: mock_user_admin
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        yield client
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def client_analyst(mock_db_session):
    """AsyncClient authed as analyst."""
    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: mock_user_analyst
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        yield client
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def client_viewer(mock_db_session):
    """AsyncClient authed as viewer."""
    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: mock_user_viewer
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        yield client
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Tests: Auth & Roles
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_auth_login_success(mock_db_session, monkeypatch):
    """Test standard OAuth2 flow success via local mocking."""
    # Mock passlib to bypass bcrypt version check crash in tests
    monkeypatch.setattr("defmon.api.auth.verify_password", lambda p, h: p == "password123")
    
    pw_hash = "fakehash"
    
    mock_user = User(
        id=1, username="admin", hashed_password=pw_hash,
        role=UserRole.ADMIN, is_active=True, is_locked=False
    )
    
    mock_scalar = MagicMock()
    mock_scalar.scalar_one_or_none.return_value = mock_user
    mock_db_session.execute.return_value = mock_scalar
    
    app.dependency_overrides[get_db] = lambda: mock_db_session
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.post(
            "/api/auth/login",
            data={"username": "admin", "password": "password123"}
        )
    app.dependency_overrides.clear()
    
    assert response.status_code == 200
    assert "access_token" in response.json()


@pytest.mark.asyncio
async def test_auth_login_failure(mock_db_session, monkeypatch):
    """Test login failure."""
    monkeypatch.setattr("defmon.api.auth.verify_password", lambda p, h: False)
    mock_scalar = MagicMock()
    mock_scalar.scalar_one_or_none.return_value = None
    mock_db_session.execute.return_value = mock_scalar
    
    app.dependency_overrides[get_db] = lambda: mock_db_session
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.post(
            "/api/auth/login",
            data={"username": "admin", "password": "wrongpassword"}
        )
    app.dependency_overrides.clear()
    
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Tests: Alerts Endpoints
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_get_alerts_unauth(client_unauth):
    """Unauthenticated users should get 401."""
    resp = await client_unauth.get("/api/alerts")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_get_alerts_admin(client_admin, mock_db_session):
    """Admins should be able to read alerts."""
    mock_scalar = MagicMock()
    mock_alert = Alert(
        id=1, alert_id=uuid.uuid4(), timestamp=datetime.now(timezone.utc),
        ip="10.0.0.1", rule_id="XYZ", severity="High", description="desc"
    )
    mock_scalar.scalars().all.return_value = [mock_alert]
    mock_db_session.execute.return_value = mock_scalar
    
    resp = await client_admin.get("/api/alerts")
    assert resp.status_code == 200
    assert len(resp.json()) == 1


@pytest.mark.asyncio
async def test_get_alerts_summary(client_analyst, mock_db_session):
    """Test alert summary endpoint."""
    mock_scalar = MagicMock()
    mock_scalar.all.return_value = [("Critical", 5), ("High", 10)]
    mock_db_session.execute.return_value = mock_scalar
    
    resp = await client_analyst.get("/api/alerts/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert data["Critical"] == 5
    assert data["High"] == 10
    assert data["Low"] == 0


@pytest.mark.asyncio
async def test_get_top_offenders(client_viewer, mock_db_session):
    """Test top offenders endpoint."""
    mock_scalar = MagicMock()
    mock_scalar.all.return_value = [("10.0.0.1", 100), ("10.0.0.2", 50)]
    mock_db_session.execute.return_value = mock_scalar
    
    resp = await client_viewer.get("/api/alerts/top-offenders")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    assert data[0]["ip"] == "10.0.0.1"
    assert data[0]["alerts"] == 100


# ---------------------------------------------------------------------------
# Tests: Incidents Endpoints
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_get_incidents(client_viewer, mock_db_session):
    """Test getting incidents."""
    mock_scalar = MagicMock()
    mock_incident = Incident(
        id=1, case_id=uuid.uuid4(), alert_id=uuid.uuid4(),
        status=IncidentStatus.OPEN, severity=SeverityLevel.HIGH,
        created_at=datetime.now(timezone.utc)
    )
    mock_scalar.scalars().all.return_value = [mock_incident]
    mock_db_session.execute.return_value = mock_scalar
    
    resp = await client_viewer.get("/api/incidents")
    assert resp.status_code == 200
    assert len(resp.json()) == 1


@pytest.mark.asyncio
async def test_get_incident_detail(client_analyst, mock_db_session):
    """Test getting an incident by ID."""
    mock_scalar = MagicMock()
    case_uid = uuid.uuid4()
    mock_incident = Incident(
        id=1, case_id=case_uid, alert_id=uuid.uuid4(),
        status=IncidentStatus.OPEN, severity=SeverityLevel.HIGH,
        created_at=datetime.now(timezone.utc)
    )
    mock_scalar.scalar_one_or_none.return_value = mock_incident
    mock_db_session.execute.return_value = mock_scalar
    
    resp = await client_analyst.get(f"/api/incidents/{case_uid}")
    assert resp.status_code == 200
    assert resp.json()["case_id"] == str(case_uid)


@pytest.mark.asyncio
async def test_get_incident_detail_not_found(client_admin, mock_db_session):
    """Test 404 for missing incident."""
    mock_scalar = MagicMock()
    mock_scalar.scalar_one_or_none.return_value = None
    mock_db_session.execute.return_value = mock_scalar
    
    resp = await client_admin.get(f"/api/incidents/{str(uuid.uuid4())}")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Tests: Metrics
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_get_metrics(client_analyst, mock_db_session):
    """Test MTTR and MTTD calculation."""
    # First execute is for MTTD, second is for MTTR
    now = datetime.now(timezone.utc)
    
    # Mock Alerts
    alert_1 = Alert(created_at=now, timestamp=now)
    # Mock Incidents
    incident_1 = Incident(created_at=now, closed_at=now)
    
    mock_scalar1 = MagicMock()
    mock_scalar1.scalars().all.return_value = [alert_1]
    mock_scalar2 = MagicMock()
    mock_scalar2.scalars().all.return_value = [incident_1]
    
    mock_db_session.execute.side_effect = [mock_scalar1, mock_scalar2]
    
    resp = await client_analyst.get("/api/metrics")
    assert resp.status_code == 200
    data = resp.json()
    assert "mttd_seconds" in data
    assert "mttr_seconds" in data


# ---------------------------------------------------------------------------
# Tests: WebSocket
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_websocket_connection():
    """Test the WebSocket endpoint for alerts."""
    from fastapi.testclient import TestClient
    client = TestClient(app)
    token = create_access_token({"sub": "admin", "role": UserRole.ADMIN.value})
    
    with client.websocket_connect(f"/api/ws/alerts?token={token}") as websocket:
        websocket.send_text("ping")
        data = websocket.receive_text()
        assert data == "pong"


@pytest.mark.asyncio
async def test_update_alert_status(client_analyst, mock_db_session):
    """Analyst can acknowledge/resolve an alert."""
    alert_uuid = uuid.uuid4()
    mock_alert = Alert(
        id=1,
        alert_id=alert_uuid,
        timestamp=datetime.now(timezone.utc),
        ip="10.0.0.1",
        rule_id="SQLI_001",
        severity=SeverityLevel.HIGH,
        description="desc",
        status="new",
    )
    mock_scalar = MagicMock()
    mock_scalar.scalar_one_or_none.return_value = mock_alert
    mock_db_session.execute.return_value = mock_scalar

    resp = await client_analyst.patch(
        f"/api/alerts/{alert_uuid}/status",
        json={"status": "acknowledged"},
    )

    assert resp.status_code == 200
    assert resp.json()["status"] == "acknowledged"


@pytest.mark.asyncio
async def test_update_incident_status(client_admin, mock_db_session):
    """Admin can close incidents."""
    case_id = uuid.uuid4()
    mock_incident = Incident(
        id=1,
        case_id=case_id,
        alert_id=uuid.uuid4(),
        status=IncidentStatus.OPEN,
        severity=SeverityLevel.HIGH,
        created_at=datetime.now(timezone.utc),
    )
    mock_scalar = MagicMock()
    mock_scalar.scalar_one_or_none.return_value = mock_incident
    mock_db_session.execute.return_value = mock_scalar

    resp = await client_admin.patch(
        f"/api/incidents/{case_id}/status",
        json={"status": IncidentStatus.CLOSED.value},
    )

    assert resp.status_code == 200
    assert resp.json()["status"] == IncidentStatus.CLOSED.value


@pytest.mark.asyncio
async def test_admin_create_user(client_admin, mock_db_session):
    """Admin can create a user account."""
    mock_lookup = MagicMock()
    mock_lookup.scalar_one_or_none.return_value = None
    mock_db_session.execute.return_value = mock_lookup

    async def _fake_flush():
        args = mock_db_session.add.call_args.args
        if args:
            args[0].id = 99

    mock_db_session.flush.side_effect = _fake_flush

    resp = await client_admin.post(
        "/api/admin/users",
        json={"username": "new_user", "password": "pass1234", "role": "viewer"},
    )

    assert resp.status_code == 201
    assert resp.json()["username"] == "new_user"


@pytest.mark.asyncio
async def test_list_logs(client_viewer):
    """Viewer can list available log files."""
    resp = await client_viewer.get("/api/logs")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_get_log_content(client_viewer):
    """Viewer can open log file content from workspace."""
    temp_log = Path("data/test_runtime.log")
    temp_log.write_text("line1\nline2\n", encoding="utf-8")
    try:
        resp = await client_viewer.get("/api/logs/content", params={"path": "data/test_runtime.log", "lines": 50})
        assert resp.status_code == 200
        assert "line1" in resp.json()["content"]
    finally:
        if temp_log.exists():
            temp_log.unlink()
