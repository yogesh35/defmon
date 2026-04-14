"""Tests for DefMon Detection Engine (detection/engine.py) — Phase 3.

Required tests from project spec:
1. SQLi hit
2. XSS hit
3. Brute-force trigger
4. Threshold not triggered below limit
5. Dedup suppression
6. Behavioral anomaly trigger
7. Engine state reset

Plus additional edge-case and integration tests.
"""

import asyncio
import time
from datetime import datetime, timezone

import pytest

from defmon.parser import LogEvent
from defmon.detection.engine import (
    DetectionEngine,
    Alert,
    _SlidingWindowCounter,
    _BehavioralBaseline,
)


# ---------------------------------------------------------------------------
# Helper: Create LogEvent for testing
# ---------------------------------------------------------------------------
def _make_event(
    ip: str = "192.168.1.100",
    method: str = "GET",
    uri: str = "/index.html",
    status_code: int = 200,
    bytes_sent: int = 1024,
    user_agent: str = "Mozilla/5.0",
    referrer: str = "-",
    timestamp: datetime = None,
) -> LogEvent:
    """Create a LogEvent for testing with sensible defaults."""
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)
    return LogEvent(
        timestamp=timestamp,
        ip=ip,
        method=method,
        uri=uri,
        status_code=status_code,
        bytes_sent=bytes_sent,
        user_agent=user_agent,
        referrer=referrer,
        raw_line=f'{ip} - - [10/Oct/2024:13:55:36 +0000] "{method} {uri} HTTP/1.1" {status_code} {bytes_sent} "{referrer}" "{user_agent}"',
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def engine() -> DetectionEngine:
    """Create a DetectionEngine instance with default config."""
    return DetectionEngine()


# ---------------------------------------------------------------------------
# 1. SQL Injection Detection
# ---------------------------------------------------------------------------
class TestSQLiDetection:
    """Tests for SQL Injection rule-based detection."""

    @pytest.mark.asyncio
    async def test_sqli_union_select(self, engine):
        """UNION SELECT pattern must trigger SQLI_001 alert."""
        event = _make_event(uri="/search?q=1'+UNION+SELECT+*+FROM+users--")
        alerts = await engine.analyze(event)
        sqli_alerts = [a for a in alerts if a.rule_id == "SQLI_001"]
        assert len(sqli_alerts) >= 1
        assert sqli_alerts[0].severity == "Critical"

    @pytest.mark.asyncio
    async def test_sqli_or_1_equals_1(self, engine):
        """OR 1=1 pattern must trigger SQLi detection."""
        event = _make_event(uri="/login?user=admin'+OR+1=1--")
        alerts = await engine.analyze(event)
        sqli_alerts = [a for a in alerts if a.rule_id == "SQLI_001"]
        assert len(sqli_alerts) >= 1

    @pytest.mark.asyncio
    async def test_sqli_drop_table(self, engine):
        """DROP TABLE pattern must trigger SQLi detection."""
        event = _make_event(uri="/api?id=1;+DROP+TABLE+users--")
        alerts = await engine.analyze(event)
        sqli_alerts = [a for a in alerts if a.rule_id == "SQLI_001"]
        assert len(sqli_alerts) >= 1

    @pytest.mark.asyncio
    async def test_sqli_alert_has_correct_fields(self, engine):
        """SQLi alert must have all required Alert fields."""
        event = _make_event(uri="/search?q=1+OR+1=1--")
        alerts = await engine.analyze(event)
        assert len(alerts) >= 1
        alert = alerts[0]
        assert alert.alert_id is not None
        assert alert.timestamp is not None
        assert alert.ip == "192.168.1.100"
        assert alert.severity == "Critical"
        assert alert.risk_score > 0

    @pytest.mark.asyncio
    async def test_clean_uri_no_sqli(self, engine):
        """Normal URI must NOT trigger SQLi detection."""
        event = _make_event(uri="/about/contact")
        alerts = await engine.analyze(event)
        sqli_alerts = [a for a in alerts if a.rule_id == "SQLI_001"]
        assert len(sqli_alerts) == 0


# ---------------------------------------------------------------------------
# 2. XSS Detection
# ---------------------------------------------------------------------------
class TestXSSDetection:
    """Tests for Cross-Site Scripting detection."""

    @pytest.mark.asyncio
    async def test_xss_script_tag(self, engine):
        """<script> tag in URI must trigger XSS_001 alert."""
        event = _make_event(uri="/comment?text=<script>alert(1)</script>")
        alerts = await engine.analyze(event)
        xss_alerts = [a for a in alerts if a.rule_id == "XSS_001"]
        assert len(xss_alerts) >= 1
        assert xss_alerts[0].severity == "High"

    @pytest.mark.asyncio
    async def test_xss_onerror(self, engine):
        """onerror event handler must trigger XSS detection."""
        event = _make_event(uri="/img?src=<img+src=x+onerror=alert(1)>")
        alerts = await engine.analyze(event)
        xss_alerts = [a for a in alerts if a.rule_id == "XSS_001"]
        assert len(xss_alerts) >= 1

    @pytest.mark.asyncio
    async def test_xss_javascript_protocol(self, engine):
        """javascript: protocol must trigger XSS detection."""
        event = _make_event(uri="/redirect?url=javascript:alert('xss')")
        alerts = await engine.analyze(event)
        xss_alerts = [a for a in alerts if a.rule_id == "XSS_001"]
        assert len(xss_alerts) >= 1

    @pytest.mark.asyncio
    async def test_clean_uri_no_xss(self, engine):
        """Normal URI must NOT trigger XSS detection."""
        event = _make_event(uri="/api/users?page=1&limit=10")
        alerts = await engine.analyze(event)
        xss_alerts = [a for a in alerts if a.rule_id == "XSS_001"]
        assert len(xss_alerts) == 0


# ---------------------------------------------------------------------------
# 3. Directory Traversal Detection
# ---------------------------------------------------------------------------
class TestTraversalDetection:
    """Tests for directory traversal detection."""

    @pytest.mark.asyncio
    async def test_traversal_dotdot(self, engine):
        """../ pattern must trigger TRAVERSAL_001 alert."""
        event = _make_event(uri="/static/../../../../etc/passwd")
        alerts = await engine.analyze(event)
        traversal_alerts = [a for a in alerts if a.rule_id == "TRAVERSAL_001"]
        assert len(traversal_alerts) >= 1
        assert traversal_alerts[0].severity == "High"

    @pytest.mark.asyncio
    async def test_traversal_encoded(self, engine):
        """URL-encoded traversal (%2e%2e%2f) must trigger detection."""
        event = _make_event(uri="/download?file=%2e%2e%2f%2e%2e%2fetc/passwd")
        alerts = await engine.analyze(event)
        traversal_alerts = [a for a in alerts if a.rule_id == "TRAVERSAL_001"]
        assert len(traversal_alerts) >= 1

    @pytest.mark.asyncio
    async def test_clean_uri_no_traversal(self, engine):
        """Normal URI must NOT trigger traversal detection."""
        event = _make_event(uri="/static/css/style.css")
        alerts = await engine.analyze(event)
        traversal_alerts = [a for a in alerts if a.rule_id == "TRAVERSAL_001"]
        assert len(traversal_alerts) == 0


# ---------------------------------------------------------------------------
# 4. Brute-Force Threshold Detection
# ---------------------------------------------------------------------------
class TestBruteForceDetection:
    """Tests for brute-force login threshold detection."""

    @pytest.mark.asyncio
    async def test_brute_force_trigger(self, engine):
        """Exceeding max_failed_logins threshold must trigger brute-force alert."""
        all_alerts = []
        base_ts = time.time()

        # Send 15 failed login attempts (threshold is 10)
        for i in range(15):
            event = _make_event(
                ip="10.0.0.99",
                method="POST",
                uri="/api/login",
                status_code=401,
                timestamp=datetime.fromtimestamp(base_ts + i, tz=timezone.utc),
            )
            alerts = await engine.analyze(event)
            all_alerts.extend(alerts)

        brute_alerts = [a for a in all_alerts if a.rule_id == "BRUTE_FORCE_001"]
        assert len(brute_alerts) >= 1
        assert brute_alerts[0].ip == "10.0.0.99"

    @pytest.mark.asyncio
    async def test_threshold_not_triggered_below_limit(self, engine):
        """Below-threshold login failures must NOT trigger brute-force alert."""
        all_alerts = []
        base_ts = time.time()

        # Send only 5 failed logins (threshold is 10)
        for i in range(5):
            event = _make_event(
                ip="10.0.0.50",
                method="POST",
                uri="/api/login",
                status_code=401,
                timestamp=datetime.fromtimestamp(base_ts + i, tz=timezone.utc),
            )
            alerts = await engine.analyze(event)
            all_alerts.extend(alerts)

        brute_alerts = [a for a in all_alerts if a.rule_id == "BRUTE_FORCE_001"]
        assert len(brute_alerts) == 0

    @pytest.mark.asyncio
    async def test_brute_force_different_ips_independent(self, engine):
        """Brute-force counters must be independent per IP."""
        base_ts = time.time()

        # 5 failures from IP A
        for i in range(5):
            event = _make_event(
                ip="10.0.0.1", method="POST", uri="/api/login", status_code=401,
                timestamp=datetime.fromtimestamp(base_ts + i, tz=timezone.utc),
            )
            await engine.analyze(event)

        # 5 failures from IP B — neither should trigger
        all_alerts = []
        for i in range(5):
            event = _make_event(
                ip="10.0.0.2", method="POST", uri="/api/login", status_code=401,
                timestamp=datetime.fromtimestamp(base_ts + i, tz=timezone.utc),
            )
            alerts = await engine.analyze(event)
            all_alerts.extend(alerts)

        brute_alerts = [a for a in all_alerts if a.rule_id == "BRUTE_FORCE_001"]
        assert len(brute_alerts) == 0  # Neither IP hit 10


# ---------------------------------------------------------------------------
# 5. Scanning Detection (404 Threshold)
# ---------------------------------------------------------------------------
class TestScanDetection:
    """Tests for path/port scanning via 404 rate threshold."""

    @pytest.mark.asyncio
    async def test_scan_trigger(self, engine):
        """Exceeding max_404_rate must trigger SCAN_001 alert."""
        all_alerts = []
        base_ts = time.time()

        # Send 55 404 responses from same IP (threshold is 50)
        for i in range(55):
            event = _make_event(
                ip="10.10.10.10",
                uri=f"/admin/path{i}",
                status_code=404,
                timestamp=datetime.fromtimestamp(base_ts + i, tz=timezone.utc),
            )
            alerts = await engine.analyze(event)
            all_alerts.extend(alerts)

        scan_alerts = [a for a in all_alerts if a.rule_id == "SCAN_001"]
        assert len(scan_alerts) >= 1

    @pytest.mark.asyncio
    async def test_scan_not_triggered_below_limit(self, engine):
        """Below-threshold 404s must NOT trigger scan alert."""
        all_alerts = []
        base_ts = time.time()

        for i in range(10):
            event = _make_event(
                ip="10.10.10.20",
                uri=f"/missing{i}",
                status_code=404,
                timestamp=datetime.fromtimestamp(base_ts + i, tz=timezone.utc),
            )
            alerts = await engine.analyze(event)
            all_alerts.extend(alerts)

        scan_alerts = [a for a in all_alerts if a.rule_id == "SCAN_001"]
        assert len(scan_alerts) == 0


# ---------------------------------------------------------------------------
# 6. Deduplication
# ---------------------------------------------------------------------------
class TestDeduplication:
    """Tests for alert deduplication within dedup_window_seconds."""

    @pytest.mark.asyncio
    async def test_dedup_suppresses_duplicate(self, engine):
        """Same (ip, rule_id) within dedup window must be suppressed."""
        event1 = _make_event(ip="1.2.3.4", uri="/search?q='+OR+1=1--")
        event2 = _make_event(ip="1.2.3.4", uri="/other?q='+OR+1=1--")

        alerts1 = await engine.analyze(event1)
        alerts2 = await engine.analyze(event2)

        # First should fire, second should be deduplicated
        sqli_1 = [a for a in alerts1 if a.rule_id == "SQLI_001"]
        sqli_2 = [a for a in alerts2 if a.rule_id == "SQLI_001"]

        assert len(sqli_1) >= 1
        assert len(sqli_2) == 0  # Deduplicated

    @pytest.mark.asyncio
    async def test_dedup_different_ips_not_suppressed(self, engine):
        """Different IPs with same rule must NOT be deduplicated."""
        event1 = _make_event(ip="1.2.3.4", uri="/search?q='+OR+1=1--")
        event2 = _make_event(ip="5.6.7.8", uri="/search?q='+OR+1=1--")

        alerts1 = await engine.analyze(event1)
        alerts2 = await engine.analyze(event2)

        sqli_1 = [a for a in alerts1 if a.rule_id == "SQLI_001"]
        sqli_2 = [a for a in alerts2 if a.rule_id == "SQLI_001"]

        assert len(sqli_1) >= 1
        assert len(sqli_2) >= 1  # Different IP, not deduplicated

    @pytest.mark.asyncio
    async def test_dedup_different_rules_not_suppressed(self, engine):
        """Same IP with different rules must NOT be deduplicated."""
        event1 = _make_event(ip="1.2.3.4", uri="/search?q='+OR+1=1--")
        event2 = _make_event(ip="1.2.3.4", uri="/path/../../../etc/passwd")

        alerts1 = await engine.analyze(event1)
        alerts2 = await engine.analyze(event2)

        # Both should fire (different rule_ids)
        assert len(alerts1) >= 1
        assert len(alerts2) >= 1


# ---------------------------------------------------------------------------
# 7. Behavioral Anomaly Detection
# ---------------------------------------------------------------------------
class TestBehavioralDetection:
    """Tests for behavioral anomaly detection based on request rate baseline."""

    @pytest.mark.asyncio
    async def test_behavioral_anomaly_trigger(self):
        """Sudden rate spike above baseline × multiplier must trigger anomaly alert."""
        # Use a custom engine with lower min_samples for easier testing
        from defmon.detection.engine import _BehavioralBaseline

        engine = DetectionEngine()
        # Override behavioral detector with lower thresholds for testing
        engine._behavioral = _BehavioralBaseline(
            baseline_window_minutes=60,
            anomaly_multiplier=2.0,
            min_samples=5,
        )

        all_alerts = []
        base_ts = time.time()

        # Build baseline: 10 requests spread over 600 seconds (1 req/min)
        for i in range(10):
            event = _make_event(
                ip="172.16.0.99",
                uri="/api/status",
                timestamp=datetime.fromtimestamp(base_ts + i * 60, tz=timezone.utc),
            )
            await engine.analyze(event)

        # Spike: 50 requests within 10 seconds (300 req/min vs baseline ~1)
        spike_ts = base_ts + 600
        for i in range(50):
            event = _make_event(
                ip="172.16.0.99",
                uri="/api/data",
                timestamp=datetime.fromtimestamp(spike_ts + i * 0.2, tz=timezone.utc),
            )
            alerts = await engine.analyze(event)
            all_alerts.extend(alerts)

        anomaly_alerts = [a for a in all_alerts if a.rule_id == "ANOMALY_001"]
        # Should have at least one anomaly alert due to rate spike
        assert len(anomaly_alerts) >= 1

    @pytest.mark.asyncio
    async def test_behavioral_no_anomaly_normal_rate(self, engine):
        """Steady normal rate must NOT trigger behavioral anomaly."""
        all_alerts = []
        base_ts = time.time()

        # 20 requests evenly spread (no spike)
        for i in range(20):
            event = _make_event(
                ip="172.16.0.50",
                uri="/page",
                timestamp=datetime.fromtimestamp(base_ts + i * 10, tz=timezone.utc),
            )
            alerts = await engine.analyze(event)
            all_alerts.extend(alerts)

        anomaly_alerts = [a for a in all_alerts if a.rule_id == "ANOMALY_001"]
        assert len(anomaly_alerts) == 0


# ---------------------------------------------------------------------------
# 8. Engine State Reset
# ---------------------------------------------------------------------------
class TestEngineReset:
    """Tests for engine state reset."""

    @pytest.mark.asyncio
    async def test_reset_clears_dedup(self, engine):
        """Reset must clear dedup cache so same alert fires again."""
        event = _make_event(ip="9.9.9.9", uri="/search?q='+OR+1=1--")

        alerts1 = await engine.analyze(event)
        assert len([a for a in alerts1 if a.rule_id == "SQLI_001"]) >= 1

        # Same event should be deduplicated
        alerts2 = await engine.analyze(event)
        assert len([a for a in alerts2 if a.rule_id == "SQLI_001"]) == 0

        # Reset engine state
        await engine.reset()

        # After reset, same event should fire again
        alerts3 = await engine.analyze(event)
        assert len([a for a in alerts3 if a.rule_id == "SQLI_001"]) >= 1

    @pytest.mark.asyncio
    async def test_reset_clears_counters(self, engine):
        """Reset must clear threshold counters."""
        await engine.reset()
        assert engine.stats["dedup_cache_size"] == 0
        assert engine.stats["tracked_ips"] == 0

    @pytest.mark.asyncio
    async def test_reset_clears_frequency(self, engine):
        """Reset must clear frequency tracking for risk scoring."""
        event = _make_event(ip="8.8.8.8", uri="/q='+OR+1=1--")
        await engine.analyze(event)

        assert engine.stats["tracked_ips"] >= 1

        await engine.reset()
        assert engine.stats["tracked_ips"] == 0


# ---------------------------------------------------------------------------
# 9. Risk Scoring
# ---------------------------------------------------------------------------
class TestRiskScoring:
    """Tests for the risk score calculation."""

    @pytest.mark.asyncio
    async def test_critical_has_highest_score(self, engine):
        """Critical severity alerts must have higher risk scores than lower severities."""
        # SQLi = Critical
        sqli_event = _make_event(ip="100.0.0.1", uri="/q='+OR+1=1--")
        sqli_alerts = await engine.analyze(sqli_event)

        await engine.reset()

        # Traversal = High
        trav_event = _make_event(ip="100.0.0.2", uri="/path/../../../etc/passwd")
        trav_alerts = await engine.analyze(trav_event)

        if sqli_alerts and trav_alerts:
            assert sqli_alerts[0].risk_score > trav_alerts[0].risk_score

    @pytest.mark.asyncio
    async def test_risk_score_positive(self, engine):
        """Risk score must always be a positive number."""
        event = _make_event(uri="/search?q='+OR+1=1--")
        alerts = await engine.analyze(event)
        assert len(alerts) >= 1
        assert alerts[0].risk_score > 0

    @pytest.mark.asyncio
    async def test_threat_intel_increases_score(self, engine):
        """Higher threat intel score must increase the risk score."""
        event1 = _make_event(ip="200.0.0.1", uri="/q='+OR+1=1--")
        alerts1 = await engine.analyze(event1, threat_intel_score=0)

        await engine.reset()

        event2 = _make_event(ip="200.0.0.2", uri="/q='+OR+1=1--")
        alerts2 = await engine.analyze(event2, threat_intel_score=100)

        if alerts1 and alerts2:
            assert alerts2[0].risk_score > alerts1[0].risk_score


# ---------------------------------------------------------------------------
# 10. Alert Dataclass
# ---------------------------------------------------------------------------
class TestAlertDataclass:
    """Tests for the Alert dataclass."""

    def test_alert_to_dict(self):
        """Alert.to_dict() must return a serializable dictionary."""
        alert = Alert(
            alert_id="test-id",
            timestamp=datetime.now(timezone.utc),
            ip="1.2.3.4",
            rule_id="TEST_001",
            severity="High",
            description="Test alert",
            raw_event="raw log line",
            risk_score=42.5,
        )
        d = alert.to_dict()
        assert isinstance(d, dict)
        assert d["alert_id"] == "test-id"
        assert d["severity"] == "High"
        assert isinstance(d["timestamp"], str)

    def test_alert_has_uuid(self):
        """Alert alert_id must be set."""
        alert = Alert(
            alert_id="abc-123",
            timestamp=datetime.now(timezone.utc),
            ip="1.2.3.4",
            rule_id="TEST",
            severity="Low",
            description="test",
            raw_event="raw",
            risk_score=10,
        )
        assert alert.alert_id == "abc-123"

    def test_alert_tags_default_empty(self):
        """Alert tags must default to empty list."""
        alert = Alert(
            alert_id="x",
            timestamp=datetime.now(timezone.utc),
            ip="1.1.1.1",
            rule_id="R",
            severity="Low",
            description="d",
            raw_event="r",
            risk_score=0,
        )
        assert alert.tags == []

    def test_alert_optional_username(self):
        """Alert username must default to None."""
        alert = Alert(
            alert_id="x",
            timestamp=datetime.now(timezone.utc),
            ip="1.1.1.1",
            rule_id="R",
            severity="Low",
            description="d",
            raw_event="r",
            risk_score=0,
        )
        assert alert.username is None


# ---------------------------------------------------------------------------
# 11. Sliding Window Counter Unit Tests
# ---------------------------------------------------------------------------
class TestSlidingWindowCounter:
    """Tests for the _SlidingWindowCounter internal class."""

    def test_record_increments(self):
        """Recording events must increment the count."""
        counter = _SlidingWindowCounter(window_seconds=60)
        assert counter.record("ip1", ts=100.0) == 1
        assert counter.record("ip1", ts=101.0) == 2
        assert counter.record("ip1", ts=102.0) == 3

    def test_expired_entries_evicted(self):
        """Entries outside the window must be evicted."""
        counter = _SlidingWindowCounter(window_seconds=10)
        counter.record("ip1", ts=100.0)
        counter.record("ip1", ts=105.0)

        # At ts=112, entry at 100.0 is outside window (112 - 10 = 102 cutoff)
        # Entry at 105.0 is still within window, plus new entry at 112.0
        count = counter.record("ip1", ts=112.0)
        assert count == 2  # 105.0 and 112.0

    def test_different_keys_independent(self):
        """Different keys must have independent counters."""
        counter = _SlidingWindowCounter(window_seconds=60)
        counter.record("ip1", ts=100.0)
        counter.record("ip1", ts=101.0)
        count = counter.record("ip2", ts=102.0)
        assert count == 1  # ip2 has only 1 event

    def test_reset_clears_all(self):
        """Reset must clear all tracked events."""
        counter = _SlidingWindowCounter(window_seconds=60)
        counter.record("ip1", ts=100.0)
        counter.record("ip2", ts=101.0)
        counter.reset()
        assert counter.get_count("ip1") == 0
        assert counter.get_count("ip2") == 0


# ---------------------------------------------------------------------------
# 12. Behavioral Baseline Unit Tests
# ---------------------------------------------------------------------------
class TestBehavioralBaseline:
    """Tests for the _BehavioralBaseline internal class."""

    def test_below_min_samples_no_anomaly(self):
        """Below min_samples, no anomaly should be reported."""
        baseline = _BehavioralBaseline(
            baseline_window_minutes=60,
            anomaly_multiplier=3.0,
            min_samples=10,
        )
        for i in range(5):  # Only 5 samples (below min 10)
            is_anomaly, _, _ = baseline.record_and_check("ip1", ts=100.0 + i)

        assert is_anomaly is False

    def test_reset_clears_baselines(self):
        """Reset must clear all baseline data."""
        baseline = _BehavioralBaseline()
        for i in range(15):
            baseline.record_and_check("ip1", ts=100.0 + i * 10)
        baseline.reset()
        is_anomaly, _, _ = baseline.record_and_check("ip1", ts=1000.0)
        assert is_anomaly is False  # No baseline after reset


# ---------------------------------------------------------------------------
# 13. Engine Stats
# ---------------------------------------------------------------------------
class TestEngineStats:
    """Tests for engine statistics."""

    def test_stats_has_required_keys(self, engine):
        """Engine stats must contain required keys."""
        stats = engine.stats
        assert "rules_loaded" in stats
        assert "dedup_window_seconds" in stats
        assert "dedup_cache_size" in stats
        assert "tracked_ips" in stats

    def test_stats_rules_loaded(self, engine):
        """Stats must show at least 3 rules loaded (SQLi, XSS, Traversal)."""
        assert engine.stats["rules_loaded"] >= 3

    @pytest.mark.asyncio
    async def test_stats_update_after_alerts(self, engine):
        """Stats must update after generating alerts."""
        event = _make_event(ip="7.7.7.7", uri="/q='+OR+1=1--")
        await engine.analyze(event)
        assert engine.stats["tracked_ips"] >= 1
        assert engine.stats["dedup_cache_size"] >= 1


# ---------------------------------------------------------------------------
# 14. Normal Traffic — No False Positives
# ---------------------------------------------------------------------------
class TestNoFalsePositives:
    """Tests ensuring normal traffic does not trigger alerts."""

    @pytest.mark.asyncio
    async def test_normal_get_no_alerts(self, engine):
        """Normal GET request must not generate any alerts."""
        event = _make_event(uri="/index.html", status_code=200)
        alerts = await engine.analyze(event)
        # Should have no rule-based alerts (may have behavioral if enough requests)
        rule_alerts = [a for a in alerts if a.rule_id in ("SQLI_001", "XSS_001", "TRAVERSAL_001")]
        assert len(rule_alerts) == 0

    @pytest.mark.asyncio
    async def test_normal_post_no_alerts(self, engine):
        """Normal POST request with 200 status must not generate alerts."""
        event = _make_event(method="POST", uri="/api/submit", status_code=200)
        alerts = await engine.analyze(event)
        assert len(alerts) == 0

    @pytest.mark.asyncio
    async def test_normal_api_calls_no_alerts(self, engine):
        """Batch of normal API calls must not trigger any alerts."""
        uris = ["/api/users", "/api/products?page=1", "/dashboard", "/css/style.css"]
        all_alerts = []
        for uri in uris:
            event = _make_event(uri=uri)
            alerts = await engine.analyze(event)
            all_alerts.extend(alerts)

        rule_alerts = [
            a for a in all_alerts
            if a.rule_id in ("SQLI_001", "XSS_001", "TRAVERSAL_001",
                             "BRUTE_FORCE_001", "SCAN_001")
        ]
        assert len(rule_alerts) == 0


# ---------------------------------------------------------------------------
# 15. Integration: Mixed Attack Traffic
# ---------------------------------------------------------------------------
class TestMixedTraffic:
    """Integration tests with mixed attack and normal traffic."""

    @pytest.mark.asyncio
    async def test_mixed_traffic_detects_attacks_only(self, engine):
        """Engine must detect attacks in mixed traffic without false positives."""
        events = [
            _make_event(ip="1.1.1.1", uri="/index.html"),  # Normal
            _make_event(ip="2.2.2.2", uri="/search?q='+OR+1=1--"),  # SQLi
            _make_event(ip="3.3.3.3", uri="/about"),  # Normal
            _make_event(ip="4.4.4.4", uri="/x?t=<script>alert(1)</script>"),  # XSS
            _make_event(ip="5.5.5.5", uri="/css/main.css"),  # Normal
        ]

        all_alerts = []
        for event in events:
            alerts = await engine.analyze(event)
            all_alerts.extend(alerts)

        # Should have alerts from 2.2.2.2 (SQLi) and 4.4.4.4 (XSS)
        attack_ips = {a.ip for a in all_alerts}
        assert "2.2.2.2" in attack_ips
        assert "4.4.4.4" in attack_ips
        assert "1.1.1.1" not in attack_ips
        assert "3.3.3.3" not in attack_ips
        assert "5.5.5.5" not in attack_ips
