"""Detection engine — runs rules against every log event, maintains
per-IP sliding windows for threshold / behavioral detections, and
publishes alerts to the SOAR engine.

This is the analytical brain of the SIEM.
"""
import asyncio
import time
from collections import defaultdict
from typing import Optional

from backend.core.config import (
    BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW,
    SCAN_404_THRESHOLD, SCAN_404_WINDOW,
    HIGH_RATE_THRESHOLD, HIGH_RATE_WINDOW,
    MITRE_MAP, SEVERITY_SCORES, SEED_BLACKLIST,
)
from backend.detection.rules import get_all_rules, _make_alert


class DetectionEngine:
    """Stateful detection engine.

    Tracks per-IP counters for threshold and behavioral rules and
    delegates pattern matching to the rule registry.
    """

    def __init__(self):
        # sliding-window counters: ip -> list of timestamps
        self._failed_logins: dict[str, list[float]] = defaultdict(list)
        self._status_404: dict[str, list[float]] = defaultdict(list)
        self._request_rate: dict[str, list[float]] = defaultdict(list)

        # dynamic blacklist (seeded from config)
        self.blacklist: set[str] = set(SEED_BLACKLIST)

        # dedup: (rule_id, ip) -> last alert timestamp — suppress repeats within 30 s
        self._recent: dict[tuple, float] = {}

        self._lock = asyncio.Lock()

    # ── public API ────────────────────────────────────────────────────────

    async def analyze(self, log) -> list[dict]:
        """Run all detection logic against a single NormalizedLog.

        Returns a list of alert dicts (may be empty).
        """
        alerts: list[dict] = []
        now = time.time()

        # 1. Pattern-based rules (SQL-i, XSS, traversal, UA)
        for rule_fn in get_all_rules():
            result = rule_fn(log)
            if result and not self._is_dup(result["rule_id"], log.source_ip, now):
                alerts.append(result)

        # 2. Blacklisted IP
        if log.source_ip in self.blacklist:
            a = _make_alert(
                "blacklisted_ip", "Request from Blacklisted IP", "critical",
                log.source_ip,
                f"Traffic from blacklisted IP {log.source_ip}",
                log.raw_line,
            )
            if not self._is_dup("blacklisted_ip", log.source_ip, now):
                alerts.append(a)

        # 3. Threshold: brute force (401/403 on auth endpoints)
        if log.status_code in (401, 403) or (log.log_source == "auth" and log.status_code == 401):
            self._prune(self._failed_logins[log.source_ip], BRUTE_FORCE_WINDOW, now)
            self._failed_logins[log.source_ip].append(now)
            if len(self._failed_logins[log.source_ip]) >= BRUTE_FORCE_THRESHOLD:
                a = _make_alert(
                    "brute_force", "Brute Force / Password Spraying", "high",
                    log.source_ip,
                    f"{len(self._failed_logins[log.source_ip])} failed auths in {BRUTE_FORCE_WINDOW}s",
                    log.raw_line,
                )
                if not self._is_dup("brute_force", log.source_ip, now):
                    alerts.append(a)
                    self._failed_logins[log.source_ip].clear()

        # 4. Threshold: 404 scanning
        if log.status_code == 404:
            self._prune(self._status_404[log.source_ip], SCAN_404_WINDOW, now)
            self._status_404[log.source_ip].append(now)
            if len(self._status_404[log.source_ip]) >= SCAN_404_THRESHOLD:
                a = _make_alert(
                    "scan_404", "Excessive 404 Scanning", "medium",
                    log.source_ip,
                    f"{len(self._status_404[log.source_ip])} 404s in {SCAN_404_WINDOW}s",
                    log.raw_line,
                )
                if not self._is_dup("scan_404", log.source_ip, now):
                    alerts.append(a)
                    self._status_404[log.source_ip].clear()

        # 5. Threshold: high request rate
        self._prune(self._request_rate[log.source_ip], HIGH_RATE_WINDOW, now)
        self._request_rate[log.source_ip].append(now)
        if len(self._request_rate[log.source_ip]) >= HIGH_RATE_THRESHOLD:
            a = _make_alert(
                "high_request_rate", "High Request Rate (Possible DDoS)", "medium",
                log.source_ip,
                f"{len(self._request_rate[log.source_ip])} requests in {HIGH_RATE_WINDOW}s",
                log.raw_line,
            )
            if not self._is_dup("high_request_rate", log.source_ip, now):
                alerts.append(a)
                self._request_rate[log.source_ip].clear()

        return alerts

    def add_to_blacklist(self, ip: str):
        self.blacklist.add(ip)

    def remove_from_blacklist(self, ip: str):
        self.blacklist.discard(ip)

    # ── internals ─────────────────────────────────────────────────────────

    @staticmethod
    def _prune(timestamps: list[float], window: int, now: float):
        """Remove entries outside the sliding window."""
        cutoff = now - window
        while timestamps and timestamps[0] < cutoff:
            timestamps.pop(0)

    def _is_dup(self, rule_id: str, ip: str, now: float, cooldown: float = 30.0) -> bool:
        """Suppress duplicate alerts for the same (rule, ip) within cooldown."""
        key = (rule_id, ip)
        last = self._recent.get(key, 0)
        if now - last < cooldown:
            return True
        self._recent[key] = now
        return False
