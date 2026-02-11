"""Threat Intelligence Feed — external IP reputation and threat data integration.

Provides both a static threat feed (bundled known-bad IPs) and a framework
for loading external feeds. In production, integrate with AlienVault OTX,
AbuseIPDB, Shodan, etc.
"""
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from backend.core.config import DATA_DIR

THREAT_INTEL_DIR = DATA_DIR / "threat_intel"
THREAT_INTEL_DIR.mkdir(parents=True, exist_ok=True)

FEED_FILE = THREAT_INTEL_DIR / "threat_feed.json"

# Known malicious IPs from public threat feeds (static seed)
STATIC_THREAT_IPS = {
    "198.51.100.1":    {"reputation": "malicious", "source": "static_feed", "tags": ["scanner", "bruteforce"]},
    "203.0.113.66":    {"reputation": "malicious", "source": "static_feed", "tags": ["malware_c2"]},
    "192.0.2.99":      {"reputation": "malicious", "source": "static_feed", "tags": ["phishing"]},
    "10.255.255.1":    {"reputation": "suspicious", "source": "static_feed", "tags": ["tor_exit"]},
    "45.33.32.156":    {"reputation": "suspicious", "source": "static_feed", "tags": ["scanner"]},
    "185.220.101.42":  {"reputation": "malicious", "source": "static_feed", "tags": ["tor_exit", "bruteforce"]},
    "103.224.182.250": {"reputation": "malicious", "source": "static_feed", "tags": ["botnet"]},
    "77.247.181.162":  {"reputation": "suspicious", "source": "static_feed", "tags": ["tor_exit"]},
    "89.248.172.16":   {"reputation": "malicious", "source": "static_feed", "tags": ["scanner", "exploit"]},
    "23.129.64.100":   {"reputation": "suspicious", "source": "static_feed", "tags": ["tor_exit"]},
    "62.210.105.116":  {"reputation": "malicious", "source": "static_feed", "tags": ["bruteforce", "scanner"]},
    "178.62.60.166":   {"reputation": "suspicious", "source": "static_feed", "tags": ["scanner"]},
}

# Runtime cache of all threat intelligence data
_threat_cache: dict = {}


def _load_feed_file() -> dict:
    """Load saved feed data from disk."""
    if FEED_FILE.exists():
        try:
            return json.loads(FEED_FILE.read_text())
        except (json.JSONDecodeError, IOError):
            return {}
    return {}


def _save_feed_file(data: dict):
    """Persist feed data to disk."""
    FEED_FILE.write_text(json.dumps(data, indent=2, default=str))


def init_threat_intel():
    """Initialize threat intelligence cache from static + saved feeds."""
    global _threat_cache
    _threat_cache = dict(STATIC_THREAT_IPS)
    saved = _load_feed_file()
    _threat_cache.update(saved)
    return len(_threat_cache)


def lookup_ip(ip: str) -> dict | None:
    """Look up an IP in the threat intelligence database.

    Returns threat info dict or None if IP is not known-bad.
    """
    return _threat_cache.get(ip)


def enrich_alert(alert_data: dict) -> dict:
    """Enrich an alert with threat intelligence context."""
    ip = alert_data.get("source_ip", "")
    intel = lookup_ip(ip)
    if intel:
        alert_data["threat_intel"] = {
            "reputation": intel.get("reputation", "unknown"),
            "source": intel.get("source", "unknown"),
            "tags": intel.get("tags", []),
            "first_seen": intel.get("first_seen"),
        }
    else:
        alert_data["threat_intel"] = None
    return alert_data


def add_threat_indicator(ip: str, reputation: str = "malicious",
                         source: str = "manual", tags: list = None):
    """Add a new IP to the threat intelligence database."""
    entry = {
        "reputation": reputation,
        "source": source,
        "tags": tags or [],
        "first_seen": datetime.now(timezone.utc).isoformat(),
    }
    _threat_cache[ip] = entry
    # Persist
    saved = _load_feed_file()
    saved[ip] = entry
    _save_feed_file(saved)
    return entry


def get_all_indicators() -> dict:
    """Return all threat intelligence indicators."""
    return dict(_threat_cache)


def get_threat_stats() -> dict:
    """Return summary statistics of threat intelligence data."""
    total = len(_threat_cache)
    by_reputation = {}
    by_source = {}
    all_tags = {}
    for ip, info in _threat_cache.items():
        rep = info.get("reputation", "unknown")
        by_reputation[rep] = by_reputation.get(rep, 0) + 1
        src = info.get("source", "unknown")
        by_source[src] = by_source.get(src, 0) + 1
        for tag in info.get("tags", []):
            all_tags[tag] = all_tags.get(tag, 0) + 1
    return {
        "total_indicators": total,
        "by_reputation": by_reputation,
        "by_source": by_source,
        "top_tags": dict(sorted(all_tags.items(), key=lambda x: -x[1])[:10]),
    }


# Initialize on import
init_threat_intel()
