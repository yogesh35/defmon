"""Tests for DefMon configuration loader."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest


class TestSettings:
    """Tests for the Settings class and config.yaml loading."""

    def test_config_loads_successfully(self):
        """Settings must load without error from config.yaml."""
        from defmon.config import Settings

        settings = Settings()
        assert settings.app_name == "DefMon"

    def test_app_name(self):
        """App name must match config.yaml value."""
        from defmon.config import Settings

        settings = Settings()
        assert settings.app_name == "DefMon"

    def test_version(self):
        """Version must be set from config.yaml."""
        from defmon.config import Settings

        settings = Settings()
        assert settings.version == "1.0.0"

    def test_database_url_constructed(self):
        """Database URL must be constructed from environment variables."""
        from defmon.config import Settings

        settings = Settings()
        assert "postgresql+asyncpg://" in settings.database_url

    def test_detection_rules_loaded(self):
        """Detection rules must be loaded from config.yaml."""
        from defmon.config import Settings

        settings = Settings()
        rules = settings.detection_rules
        assert isinstance(rules, list)
        assert len(rules) >= 3  # SQLi, XSS, Traversal

    def test_sqli_rule_present(self):
        """SQL Injection rule SQLI_001 must be present in detection rules."""
        from defmon.config import Settings

        settings = Settings()
        rule_ids = [r["rule_id"] for r in settings.detection_rules]
        assert "SQLI_001" in rule_ids

    def test_xss_rule_present(self):
        """XSS rule XSS_001 must be present in detection rules."""
        from defmon.config import Settings

        settings = Settings()
        rule_ids = [r["rule_id"] for r in settings.detection_rules]
        assert "XSS_001" in rule_ids

    def test_traversal_rule_present(self):
        """Directory traversal rule TRAVERSAL_001 must be present."""
        from defmon.config import Settings

        settings = Settings()
        rule_ids = [r["rule_id"] for r in settings.detection_rules]
        assert "TRAVERSAL_001" in rule_ids

    def test_threshold_config(self):
        """Threshold config must contain required keys."""
        from defmon.config import Settings

        settings = Settings()
        tc = settings.threshold_config
        assert "window_seconds" in tc
        assert "max_failed_logins" in tc
        assert "max_404_rate" in tc

    def test_behavioral_config(self):
        """Behavioral detection config must contain required keys."""
        from defmon.config import Settings

        settings = Settings()
        bc = settings.behavioral_config
        assert "baseline_window_minutes" in bc
        assert "anomaly_multiplier" in bc

    def test_dedup_window(self):
        """Deduplication window must be a positive integer."""
        from defmon.config import Settings

        settings = Settings()
        assert settings.dedup_window > 0

    def test_risk_scoring_weights(self):
        """Risk scoring config must contain severity weights."""
        from defmon.config import Settings

        settings = Settings()
        rs = settings.risk_scoring
        assert "severity_weights" in rs
        assert "Critical" in rs["severity_weights"]

    def test_log_parser_patterns(self):
        """Log parser patterns must contain apache and nginx entries."""
        from defmon.config import Settings

        settings = Settings()
        patterns = settings.log_parser_patterns
        assert "apache_combined" in patterns
        assert "nginx_access" in patterns

    def test_threat_intel_config(self):
        """Threat intel config must contain TTL and offline DB path."""
        from defmon.config import Settings

        settings = Settings()
        tic = settings.threat_intel_config
        assert "ttl_seconds" in tic
        assert "offline_db_path" in tic

    def test_soar_config(self):
        """SOAR config must contain playbook severity mappings."""
        from defmon.config import Settings

        settings = Settings()
        sc = settings.soar_config
        assert "playbooks" in sc
        assert "Critical" in sc["playbooks"]

    def test_jwt_secret_from_env(self):
        """JWT secret must be loaded from environment variable."""
        from defmon.config import Settings

        settings = Settings()
        assert len(settings.jwt_secret) > 0

    def test_raw_config_dict(self):
        """raw_config must return the full YAML config as a dict."""
        from defmon.config import Settings

        settings = Settings()
        raw = settings.raw_config
        assert isinstance(raw, dict)
        assert "app" in raw
        assert "detection" in raw

    def test_get_settings_singleton(self):
        """get_settings must return a cached singleton instance."""
        from defmon.config import get_settings

        s1 = get_settings()
        s2 = get_settings()
        assert s1 is s2
