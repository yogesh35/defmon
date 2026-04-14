"""Tests for DefMon Threat Intelligence service (utils/threat_intel.py).

Covers:
- Known malicious IP via API
- Clean IP via API
- Cache hit (TTL)
- API timeout fallback to offline DB
- Missing env var fallback to offline DB
- Offline CSV loading
- Category code to tag mapping
"""

import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch, mock_open

import httpx
import pytest
import pytest_asyncio

from defmon.utils.threat_intel import ThreatIntelResult, ThreatIntelService, _CacheEntry


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def mock_settings():
    """Create mock settings for threat intel testing."""
    settings = MagicMock()
    settings.threat_intel_config = {
        "ttl_seconds": 3600,
        "offline_db_path": "data/threat_intel.csv",
        "abuseipdb": {
            "base_url": "https://api.abuseipdb.com/api/v2",
            "max_age_days": 90,
            "confidence_threshold": 50,
        },
        "category_map": {
            3: "fraud",
            4: "ddos",
            7: "bruteforce",
            9: "scanner",
            14: "port_scan",
            22: "botnet",
            23: "tor_exit",
        },
    }
    settings.abuseipdb_key = "test-api-key"
    settings._config = {"_base_dir": str(Path(__file__).parent.parent)}
    return settings


@pytest.fixture
def mock_settings_no_key():
    """Create mock settings without AbuseIPDB API key."""
    settings = MagicMock()
    settings.threat_intel_config = {
        "ttl_seconds": 3600,
        "offline_db_path": "data/threat_intel.csv",
        "abuseipdb": {
            "base_url": "https://api.abuseipdb.com/api/v2",
            "max_age_days": 90,
            "confidence_threshold": 50,
        },
        "category_map": {
            7: "bruteforce",
            9: "scanner",
            22: "botnet",
        },
    }
    settings.abuseipdb_key = ""
    settings._config = {"_base_dir": str(Path(__file__).parent.parent)}
    return settings


@pytest.fixture
def service(mock_settings):
    """Create a ThreatIntelService with mocked settings."""
    with patch.object(ThreatIntelService, '_load_offline_db'):
        svc = ThreatIntelService(settings=mock_settings)
    return svc


@pytest.fixture
def service_no_key(mock_settings_no_key):
    """Create a ThreatIntelService without API key."""
    with patch.object(ThreatIntelService, '_load_offline_db'):
        svc = ThreatIntelService(settings=mock_settings_no_key)
    return svc


# ---------------------------------------------------------------------------
# Test: Known Malicious IP via API
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_lookup_malicious_ip_api(service):
    """AbuseIPDB returns a high-confidence malicious IP — should mark as malicious."""
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "data": {
            "ipAddress": "192.168.1.200",
            "abuseConfidenceScore": 95,
            "countryCode": "CN",
            "lastReportedAt": "2024-10-01T12:00:00Z",
            "isTor": False,
            "reports": [
                {"categories": [22, 9]},
                {"categories": [7]},
            ],
        }
    }
    mock_response.raise_for_status = MagicMock()

    with patch("defmon.utils.threat_intel.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = await service.lookup_ip("192.168.1.200")

    assert result.is_malicious is True
    assert result.confidence_score == 95
    assert result.ip == "192.168.1.200"
    assert result.country_code == "CN"
    assert "botnet" in result.tags
    assert "scanner" in result.tags


# ---------------------------------------------------------------------------
# Test: Clean IP via API
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_lookup_clean_ip_api(service):
    """AbuseIPDB returns a zero-confidence IP — should mark as not malicious."""
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "data": {
            "ipAddress": "8.8.8.8",
            "abuseConfidenceScore": 0,
            "countryCode": "US",
            "lastReportedAt": None,
            "isTor": False,
            "reports": [],
        }
    }
    mock_response.raise_for_status = MagicMock()

    with patch("defmon.utils.threat_intel.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = await service.lookup_ip("8.8.8.8")

    assert result.is_malicious is False
    assert result.confidence_score == 0
    assert result.ip == "8.8.8.8"
    assert result.tags == []


# ---------------------------------------------------------------------------
# Test: Cache Hit
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_cache_hit(service):
    """Second lookup should return cached result without hitting API."""
    cached_result = ThreatIntelResult(
        ip="10.0.0.1",
        is_malicious=True,
        confidence_score=85,
        tags=["scanner"],
        country_code="RU",
    )
    service._cache["10.0.0.1"] = _CacheEntry(
        result=cached_result,
        expires_at=time.time() + 3600,
    )

    # Should NOT call API
    with patch("defmon.utils.threat_intel.httpx.AsyncClient") as mock_client_cls:
        result = await service.lookup_ip("10.0.0.1")
        mock_client_cls.assert_not_called()

    assert result.ip == "10.0.0.1"
    assert result.is_malicious is True
    assert result.confidence_score == 85
    assert result.tags == ["scanner"]


# ---------------------------------------------------------------------------
# Test: Cache TTL Expiry
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_cache_ttl_expired(service):
    """Expired cache entry should be evicted and trigger fresh lookup."""
    expired_result = ThreatIntelResult(
        ip="10.0.0.2",
        is_malicious=False,
        confidence_score=0,
    )
    service._cache["10.0.0.2"] = _CacheEntry(
        result=expired_result,
        expires_at=time.time() - 1,  # Already expired
    )

    # Should fall through to API since cache is expired
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "data": {
            "ipAddress": "10.0.0.2",
            "abuseConfidenceScore": 70,
            "countryCode": "DE",
            "lastReportedAt": "2024-10-01T00:00:00Z",
            "isTor": False,
            "reports": [],
        }
    }
    mock_response.raise_for_status = MagicMock()

    with patch("defmon.utils.threat_intel.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = await service.lookup_ip("10.0.0.2")

    assert result.confidence_score == 70
    assert result.is_malicious is True


# ---------------------------------------------------------------------------
# Test: API Timeout Fallback to Offline DB
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_api_timeout_fallback_to_offline_db(service):
    """API timeout should fall back to offline database."""
    # Populate offline DB
    service._offline_db["1.2.3.4"] = ThreatIntelResult(
        ip="1.2.3.4",
        is_malicious=True,
        confidence_score=80,
        tags=["botnet"],
        country_code="CN",
    )

    with patch("defmon.utils.threat_intel.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = await service.lookup_ip("1.2.3.4")

    assert result.ip == "1.2.3.4"
    assert result.is_malicious is True
    assert result.confidence_score == 80
    assert "botnet" in result.tags


# ---------------------------------------------------------------------------
# Test: Missing API Key Fallback to Offline DB
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_missing_api_key_fallback(service_no_key):
    """When API key is not set, should fall back to offline database."""
    # Populate offline DB
    service_no_key._offline_db["5.6.7.8"] = ThreatIntelResult(
        ip="5.6.7.8",
        is_malicious=True,
        confidence_score=90,
        tags=["bruteforce", "scanner"],
        country_code="RU",
    )

    result = await service_no_key.lookup_ip("5.6.7.8")

    assert result.ip == "5.6.7.8"
    assert result.is_malicious is True
    assert result.confidence_score == 90


# ---------------------------------------------------------------------------
# Test: Unknown IP Returns Clean Result
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_unknown_ip_returns_clean(service_no_key):
    """IP not in offline DB and no API key should return clean result."""
    result = await service_no_key.lookup_ip("99.99.99.99")

    assert result.ip == "99.99.99.99"
    assert result.is_malicious is False
    assert result.confidence_score == 0
    assert result.tags == []


# ---------------------------------------------------------------------------
# Test: Offline CSV Loading
# ---------------------------------------------------------------------------
def test_offline_csv_loading():
    """Verify offline CSV database loads correctly."""
    settings = MagicMock()
    settings.threat_intel_config = {
        "ttl_seconds": 3600,
        "offline_db_path": "data/threat_intel.csv",
        "abuseipdb": {
            "base_url": "https://api.abuseipdb.com/api/v2",
            "max_age_days": 90,
            "confidence_threshold": 50,
        },
        "category_map": {},
    }
    settings.abuseipdb_key = ""
    # Point to the actual test project data directory
    settings._config = {"_base_dir": str(Path(__file__).parent.parent)}

    service = ThreatIntelService(settings=settings)

    # The CSV file has 15 entries
    assert service.offline_db_size > 0


# ---------------------------------------------------------------------------
# Test: Category Code to Tag Mapping
# ---------------------------------------------------------------------------
def test_category_to_tag_mapping(service):
    """Verify AbuseIPDB category codes map to human-readable tags."""
    tags = service._map_categories_to_tags([22, 9, 7, 999])

    assert "botnet" in tags
    assert "scanner" in tags
    assert "bruteforce" in tags
    # Unknown code 999 should not appear
    assert len(tags) == 3


# ---------------------------------------------------------------------------
# Test: ThreatIntelResult serialization
# ---------------------------------------------------------------------------
def test_threat_intel_result_to_dict():
    """Verify ThreatIntelResult serializes correctly."""
    result = ThreatIntelResult(
        ip="1.2.3.4",
        is_malicious=True,
        confidence_score=85,
        tags=["botnet", "scanner"],
        country_code="CN",
        last_reported_at="2024-10-01T12:00:00Z",
    )
    data = result.to_dict()

    assert data["ip"] == "1.2.3.4"
    assert data["is_malicious"] is True
    assert data["confidence_score"] == 85
    assert data["tags"] == ["botnet", "scanner"]
    assert data["country_code"] == "CN"


# ---------------------------------------------------------------------------
# Test: Cache Clear
# ---------------------------------------------------------------------------
def test_cache_clear(service):
    """Verify cache clearing works."""
    service._cache["test-ip"] = _CacheEntry(
        result=ThreatIntelResult(ip="test-ip", is_malicious=False, confidence_score=0),
        expires_at=time.time() + 3600,
    )

    assert service.cache_size == 1
    service.clear_cache()
    assert service.cache_size == 0
