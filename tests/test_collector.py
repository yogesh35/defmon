"""Tests for DefMon Log Collector (collector.py) — Phase 2.

Tests the async file watcher, incremental reading, and event processing.
"""

import asyncio
import tempfile
from pathlib import Path

import pytest

from defmon.collector import LogCollector


# ---------------------------------------------------------------------------
# Initialization Tests
# ---------------------------------------------------------------------------
class TestCollectorInit:
    """Tests for LogCollector initialization."""

    def test_default_init(self):
        """LogCollector must initialize with default log paths."""
        collector = LogCollector()
        assert collector._log_paths is not None
        assert len(collector._log_paths) >= 1

    def test_custom_paths(self, tmp_path):
        """LogCollector must accept custom log file paths."""
        path1 = tmp_path / "access.log"
        path1.touch()
        collector = LogCollector(log_paths=[str(path1)])
        assert len(collector._log_paths) == 1

    def test_initial_stats(self):
        """Initial stats must show zero counts."""
        collector = LogCollector()
        stats = collector.stats
        assert stats["total_lines_read"] == 0
        assert stats["total_events_parsed"] == 0


# ---------------------------------------------------------------------------
# Existing File Ingestion Tests
# ---------------------------------------------------------------------------
class TestIngestExisting:
    """Tests for ingesting existing log file content."""

    @pytest.mark.asyncio
    async def test_ingest_existing_file(self, tmp_path):
        """ingest_existing() must parse all lines from existing log files."""
        log_file = tmp_path / "access.log"
        log_file.write_text(
            '192.168.1.1 - - [10/Oct/2024:13:55:36 +0000] '
            '"GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n'
            '10.0.0.5 - - [10/Oct/2024:14:00:00 +0000] '
            '"POST /api/login HTTP/1.1" 401 128 "-" "curl/7.68.0"\n'
        )
        collector = LogCollector(log_paths=[str(log_file)])
        events = await collector.ingest_existing()

        assert len(events) == 2
        assert events[0].ip == "192.168.1.1"
        assert events[1].ip == "10.0.0.5"

    @pytest.mark.asyncio
    async def test_ingest_nonexistent_file(self, tmp_path):
        """ingest_existing() must handle missing files gracefully."""
        collector = LogCollector(log_paths=[str(tmp_path / "nonexistent.log")])
        events = await collector.ingest_existing()
        assert len(events) == 0

    @pytest.mark.asyncio
    async def test_ingest_updates_stats(self, tmp_path):
        """ingest_existing() must update collector statistics."""
        log_file = tmp_path / "access.log"
        log_file.write_text(
            '192.168.1.1 - - [10/Oct/2024:13:55:36 +0000] '
            '"GET /page HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n'
        )
        collector = LogCollector(log_paths=[str(log_file)])
        await collector.ingest_existing()

        stats = collector.stats
        assert stats["total_lines_read"] >= 1
        assert stats["total_events_parsed"] >= 1

    @pytest.mark.asyncio
    async def test_ingest_mixed_valid_invalid(self, tmp_path):
        """ingest_existing() must skip invalid lines and count correctly."""
        log_file = tmp_path / "mixed.log"
        log_file.write_text(
            '192.168.1.1 - - [10/Oct/2024:13:55:36 +0000] '
            '"GET /a HTTP/1.1" 200 100 "-" "Mozilla/5.0"\n'
            'INVALID LINE HERE\n'
            '10.0.0.1 - - [10/Oct/2024:14:00:00 +0000] '
            '"GET /b HTTP/1.1" 200 200 "-" "curl/7.68.0"\n'
        )
        collector = LogCollector(log_paths=[str(log_file)])
        events = await collector.ingest_existing()

        assert len(events) == 2  # only valid lines
        assert collector.stats["total_lines_read"] == 3  # all lines counted


# ---------------------------------------------------------------------------
# Callback Tests
# ---------------------------------------------------------------------------
class TestCollectorCallback:
    """Tests for the async callback mechanism."""

    @pytest.mark.asyncio
    async def test_callback_invoked(self, tmp_path):
        """Callback must be invoked for each parsed LogEvent."""
        log_file = tmp_path / "access.log"
        log_file.write_text(
            '192.168.1.1 - - [10/Oct/2024:13:55:36 +0000] '
            '"GET /page HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n'
        )
        received = []

        async def on_event(event):
            received.append(event)

        collector = LogCollector(
            log_paths=[str(log_file)],
            callback=on_event,
        )
        await collector.ingest_existing()

        assert len(received) == 1
        assert received[0].ip == "192.168.1.1"


# ---------------------------------------------------------------------------
# Stop Control Tests
# ---------------------------------------------------------------------------
class TestCollectorStop:
    """Tests for the stop control mechanism."""

    def test_stop_sets_flag(self):
        """stop() must set _running to False."""
        collector = LogCollector()
        collector._running = True
        collector.stop()
        assert collector._running is False

    def test_stats_shows_running_state(self):
        """stats must reflect the running state."""
        collector = LogCollector()
        assert collector.stats["running"] is False
