"""Tests for DefMon FastAPI health endpoint and application setup."""

from unittest.mock import patch, MagicMock
import pytest


class TestHealthEndpoint:
    """Tests for the /health endpoint — Phase 1 goal."""

    def test_health_returns_200(self):
        """Health endpoint must return HTTP 200 with correct JSON body."""
        # Import inside test to ensure env vars from conftest are applied
        from fastapi.testclient import TestClient
        from defmon.main import app

        client = TestClient(app)
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "DefMon"
        assert "version" in data

    def test_health_response_structure(self):
        """Health response must contain status, service, and version keys."""
        from fastapi.testclient import TestClient
        from defmon.main import app

        client = TestClient(app)
        response = client.get("/health")
        data = response.json()

        required_keys = {"status", "service", "version"}
        assert required_keys.issubset(data.keys())

    def test_docs_endpoint_available(self):
        """OpenAPI docs endpoint must be accessible at /docs."""
        from fastapi.testclient import TestClient
        from defmon.main import app

        client = TestClient(app)
        response = client.get("/docs")
        assert response.status_code == 200

    def test_redoc_endpoint_available(self):
        """ReDoc endpoint must be accessible at /redoc."""
        from fastapi.testclient import TestClient
        from defmon.main import app

        client = TestClient(app)
        response = client.get("/redoc")
        assert response.status_code == 200

    def test_openapi_schema(self):
        """OpenAPI JSON schema must be served at /openapi.json."""
        from fastapi.testclient import TestClient
        from defmon.main import app

        client = TestClient(app)
        response = client.get("/openapi.json")
        assert response.status_code == 200
        schema = response.json()
        assert schema["info"]["title"] == "DefMon"

    def test_cors_headers_present(self):
        """CORS headers must be set for frontend origin."""
        from fastapi.testclient import TestClient
        from defmon.main import app

        client = TestClient(app)
        response = client.options(
            "/health",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
            },
        )
        # CORS preflight should succeed
        assert response.status_code == 200
