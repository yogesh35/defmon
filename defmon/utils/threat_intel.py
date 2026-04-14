"""DefMon Threat Intelligence — IP reputation and context enrichment.

Primary source: AbuseIPDB free tier REST API.
Fallback: Local CSV database loaded on startup.
Uses in-memory hash table (dict) as L1 cache with config-driven TTL.

Complexity: O(1) average per lookup (hash table).
"""

import csv
import os
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

import httpx
from loguru import logger

from defmon.config import get_settings


# ---------------------------------------------------------------------------
# ThreatIntelResult Dataclass
# ---------------------------------------------------------------------------
@dataclass
class ThreatIntelResult:
    """Result of an IP reputation lookup.

    Contains threat intelligence context for enriching detection alerts.
    """

    ip: str
    is_malicious: bool
    confidence_score: int  # 0-100
    tags: list[str] = field(default_factory=list)
    country_code: str = ""
    last_reported_at: str = ""

    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON output."""
        return asdict(self)


# ---------------------------------------------------------------------------
# Cache Entry
# ---------------------------------------------------------------------------
@dataclass
class _CacheEntry:
    """Internal cache entry with TTL tracking."""

    result: ThreatIntelResult
    expires_at: float


# ---------------------------------------------------------------------------
# Threat Intel Service
# ---------------------------------------------------------------------------
class ThreatIntelService:
    """IP reputation lookup service with caching and offline fallback.

    Architecture:
    1. L1 cache (in-memory dict with TTL) checked first.
    2. AbuseIPDB API queried if key is available.
    3. Offline CSV database as final fallback.

    All configuration loaded from config.yaml and environment variables.
    """

    def __init__(self, settings=None) -> None:
        """Initialize threat intel service with config-driven settings.

        Args:
            settings: Optional Settings instance for dependency injection.
        """
        self._settings = settings or get_settings()
        ti_config = self._settings.threat_intel_config

        # Cache with TTL
        self._ttl_seconds: int = ti_config.get("ttl_seconds", 3600)
        self._cache: dict[str, _CacheEntry] = {}

        # AbuseIPDB config
        abuseipdb_config = ti_config.get("abuseipdb", {})
        self._api_base_url: str = abuseipdb_config.get(
            "base_url", "https://api.abuseipdb.com/api/v2"
        )
        self._max_age_days: int = abuseipdb_config.get("max_age_days", 90)
        self._confidence_threshold: int = abuseipdb_config.get(
            "confidence_threshold", 50
        )

        # API key from environment
        self._api_key: str = self._settings.abuseipdb_key

        # Category code to tag mapping from config
        self._category_map: dict[int, str] = {
            int(k): v
            for k, v in ti_config.get("category_map", {}).items()
        }

        # Offline database
        offline_db_path = ti_config.get("offline_db_path", "data/threat_intel.csv")
        self._offline_db_path: Path = Path(
            self._settings._config.get("_base_dir", Path(__file__).parent.parent.parent)
        ) / offline_db_path
        self._offline_db: dict[str, ThreatIntelResult] = {}

        # Load offline DB on startup
        self._load_offline_db()

        logger.info(
            f"ThreatIntelService initialized: "
            f"api_key={'set' if self._api_key else 'unset'}, "
            f"offline_db={len(self._offline_db)} entries, "
            f"ttl={self._ttl_seconds}s"
        )

    def _load_offline_db(self) -> None:
        """Load offline CSV threat intelligence database into memory.

        CSV format: ip,score,tags (tags are pipe-separated).
        Gracefully handles missing or malformed files.
        """
        if not self._offline_db_path.exists():
            logger.warning(
                f"Offline threat intel DB not found: {self._offline_db_path}"
            )
            return

        try:
            with open(self._offline_db_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    ip = row.get("ip", "").strip()
                    if not ip:
                        continue

                    score = int(row.get("score", "0"))
                    tags_raw = row.get("tags", "")
                    tags = [t.strip() for t in tags_raw.split("|") if t.strip()]

                    self._offline_db[ip] = ThreatIntelResult(
                        ip=ip,
                        is_malicious=score >= self._confidence_threshold,
                        confidence_score=score,
                        tags=tags,
                        country_code=row.get("country_code", ""),
                        last_reported_at=row.get("last_reported_at", ""),
                    )

            logger.info(
                f"Loaded {len(self._offline_db)} entries from offline threat intel DB"
            )
        except Exception as e:
            logger.error(f"Failed to load offline threat intel DB: {e}")

    def _get_cached(self, ip: str) -> Optional[ThreatIntelResult]:
        """Retrieve a cached result if it exists and hasn't expired.

        Args:
            ip: IP address to look up.

        Returns:
            Cached ThreatIntelResult if valid, None otherwise.
        """
        entry = self._cache.get(ip)
        if entry is None:
            return None

        if time.time() > entry.expires_at:
            # TTL expired — evict
            del self._cache[ip]
            return None

        logger.debug(f"Cache hit for IP {ip}")
        return entry.result

    def _put_cache(self, result: ThreatIntelResult) -> None:
        """Store a result in the L1 cache with TTL.

        Args:
            result: ThreatIntelResult to cache.
        """
        self._cache[result.ip] = _CacheEntry(
            result=result,
            expires_at=time.time() + self._ttl_seconds,
        )

    def _map_categories_to_tags(self, categories: list[int]) -> list[str]:
        """Map AbuseIPDB category codes to human-readable tags.

        Args:
            categories: List of AbuseIPDB category code integers.

        Returns:
            List of human-readable tag strings.
        """
        tags = []
        for code in categories:
            tag = self._category_map.get(code)
            if tag and tag not in tags:
                tags.append(tag)
        return tags

    async def _query_abuseipdb(self, ip: str) -> Optional[ThreatIntelResult]:
        """Query AbuseIPDB REST API for IP reputation data.

        Args:
            ip: IP address to look up.

        Returns:
            ThreatIntelResult on success, None on failure.
        """
        if not self._api_key:
            logger.debug("AbuseIPDB API key not set — skipping API lookup")
            return None

        url = f"{self._api_base_url}/check"
        headers = {
            "Key": self._api_key,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": str(self._max_age_days),
            "verbose": "",
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url, headers=headers, params=params)
                response.raise_for_status()

            data = response.json().get("data", {})

            # Extract categories and map to tags
            categories = data.get("reports", [])
            category_codes: list[int] = []
            if isinstance(categories, list):
                for report in categories:
                    if isinstance(report, dict):
                        category_codes.extend(report.get("categories", []))
                    elif isinstance(report, int):
                        category_codes.append(report)

            # Also check top-level usageType and isTor
            if data.get("isTor", False):
                category_codes.append(23)  # tor_exit

            tags = self._map_categories_to_tags(list(set(category_codes)))

            confidence = data.get("abuseConfidenceScore", 0)

            result = ThreatIntelResult(
                ip=ip,
                is_malicious=confidence >= self._confidence_threshold,
                confidence_score=confidence,
                tags=tags,
                country_code=data.get("countryCode", ""),
                last_reported_at=data.get("lastReportedAt", "") or "",
            )

            logger.debug(
                f"AbuseIPDB lookup: {ip} -> score={confidence}, "
                f"malicious={result.is_malicious}, tags={tags}"
            )
            return result

        except httpx.TimeoutException:
            logger.warning(f"AbuseIPDB API timeout for IP {ip}")
            return None
        except httpx.HTTPStatusError as e:
            logger.warning(
                f"AbuseIPDB API HTTP error for IP {ip}: {e.response.status_code}"
            )
            return None
        except Exception as e:
            logger.error(f"AbuseIPDB API unexpected error for IP {ip}: {e}")
            return None

    def _lookup_offline(self, ip: str) -> Optional[ThreatIntelResult]:
        """Look up IP in the offline CSV database.

        Args:
            ip: IP address to look up.

        Returns:
            ThreatIntelResult if found, None otherwise.
        """
        result = self._offline_db.get(ip)
        if result:
            logger.debug(f"Offline DB hit for IP {ip}")
        return result

    async def lookup_ip(self, ip: str) -> ThreatIntelResult:
        """Look up IP reputation with cache, API, and offline fallback.

        Lookup order:
        1. L1 cache (in-memory dict with TTL)
        2. AbuseIPDB API (if key is set)
        3. Offline CSV database
        4. Clean result (not malicious, score=0)

        Args:
            ip: IP address to look up.

        Returns:
            ThreatIntelResult with reputation data.
        """
        # 1. Check L1 cache
        cached = self._get_cached(ip)
        if cached is not None:
            return cached

        # 2. Try AbuseIPDB API
        api_result = await self._query_abuseipdb(ip)
        if api_result is not None:
            self._put_cache(api_result)
            return api_result

        # 3. Fallback to offline DB
        offline_result = self._lookup_offline(ip)
        if offline_result is not None:
            self._put_cache(offline_result)
            return offline_result

        # 4. Default: clean IP
        clean_result = ThreatIntelResult(
            ip=ip,
            is_malicious=False,
            confidence_score=0,
            tags=[],
        )
        self._put_cache(clean_result)
        return clean_result

    def clear_cache(self) -> None:
        """Clear the L1 cache."""
        self._cache.clear()
        logger.debug("Threat intel cache cleared")

    @property
    def cache_size(self) -> int:
        """Return current number of cached entries."""
        return len(self._cache)

    @property
    def offline_db_size(self) -> int:
        """Return number of entries in offline database."""
        return len(self._offline_db)
