"""Tests for DefMon Log Parser (parser.py) — Phase 2.

Required tests from project spec:
1. Valid Apache log
2. Valid Nginx log
3. Malformed line
4. Missing fields
5. IPv6 address
6. Encoded URI
7. Large byte count
8. Empty string
9. Non-HTTP protocol line
10. Throughput (1000 lines must parse in < 0.2 seconds)
Plus additional edge-case and async tests.
"""

import time
import asyncio
import tempfile
import os
from pathlib import Path

import pytest

from defmon.parser import LogParser, LogEvent, parse_file, _parse_timestamp, _parse_bytes


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def parser() -> LogParser:
    """Create a LogParser instance with default config."""
    return LogParser()


# ---------------------------------------------------------------------------
# 1. Valid Apache Combined Log Format
# ---------------------------------------------------------------------------
class TestValidApacheLog:
    """Tests for parsing valid Apache Combined Log Format lines."""

    def test_valid_apache_log_parses(self, parser):
        """A standard Apache Combined log line must parse into a LogEvent."""
        line = (
            '192.168.1.100 - frank [10/Oct/2024:13:55:36 +0000] '
            '"GET /index.html HTTP/1.1" 200 2326 '
            '"http://www.example.com/start.html" '
            '"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
        )
        event = parser.parse_line(line)
        assert event is not None
        assert isinstance(event, LogEvent)

    def test_apache_ip_extracted(self, parser, sample_apache_log):
        """IP address must be correctly extracted from Apache log."""
        event = parser.parse_line(sample_apache_log)
        assert event is not None
        assert event.ip == "192.168.1.100"

    def test_apache_method_extracted(self, parser, sample_apache_log):
        """HTTP method must be correctly extracted."""
        event = parser.parse_line(sample_apache_log)
        assert event is not None
        assert event.method == "GET"

    def test_apache_uri_extracted(self, parser, sample_apache_log):
        """URI must be correctly extracted."""
        event = parser.parse_line(sample_apache_log)
        assert event is not None
        assert event.uri == "/index.html"

    def test_apache_status_code(self, parser, sample_apache_log):
        """Status code must be an integer."""
        event = parser.parse_line(sample_apache_log)
        assert event is not None
        assert event.status_code == 200

    def test_apache_bytes_sent(self, parser, sample_apache_log):
        """Bytes sent must be parsed as integer."""
        event = parser.parse_line(sample_apache_log)
        assert event is not None
        assert event.bytes_sent == 2326

    def test_apache_user_agent(self, parser, sample_apache_log):
        """User agent must be extracted correctly."""
        event = parser.parse_line(sample_apache_log)
        assert event is not None
        assert "Mozilla" in event.user_agent

    def test_apache_referrer(self, parser, sample_apache_log):
        """Referrer must be extracted correctly."""
        event = parser.parse_line(sample_apache_log)
        assert event is not None
        assert event.referrer == "http://www.example.com/start.html"

    def test_apache_timestamp_parsed(self, parser, sample_apache_log):
        """Timestamp must be parsed into a datetime object."""
        event = parser.parse_line(sample_apache_log)
        assert event is not None
        assert event.timestamp.year == 2024
        assert event.timestamp.month == 10
        assert event.timestamp.day == 10

    def test_apache_raw_line_preserved(self, parser, sample_apache_log):
        """The original raw line must be preserved in the event."""
        event = parser.parse_line(sample_apache_log)
        assert event is not None
        assert event.raw_line == sample_apache_log.strip()


# ---------------------------------------------------------------------------
# 2. Valid Nginx Access Log
# ---------------------------------------------------------------------------
class TestValidNginxLog:
    """Tests for parsing valid Nginx access log lines."""

    def test_valid_nginx_log_parses(self, parser, sample_nginx_log):
        """A standard Nginx access log line must parse into a LogEvent."""
        event = parser.parse_line(sample_nginx_log)
        assert event is not None
        assert isinstance(event, LogEvent)

    def test_nginx_ip_extracted(self, parser, sample_nginx_log):
        """IP address must be correctly extracted from Nginx log."""
        event = parser.parse_line(sample_nginx_log)
        assert event is not None
        assert event.ip == "10.0.0.1"

    def test_nginx_post_method(self, parser, sample_nginx_log):
        """POST method must be correctly extracted."""
        event = parser.parse_line(sample_nginx_log)
        assert event is not None
        assert event.method == "POST"

    def test_nginx_401_status(self, parser, sample_nginx_log):
        """401 status code must be parsed correctly."""
        event = parser.parse_line(sample_nginx_log)
        assert event is not None
        assert event.status_code == 401

    def test_nginx_uri(self, parser, sample_nginx_log):
        """URI must be extracted from Nginx log."""
        event = parser.parse_line(sample_nginx_log)
        assert event is not None
        assert event.uri == "/api/login"


# ---------------------------------------------------------------------------
# 3. Malformed Line
# ---------------------------------------------------------------------------
class TestMalformedLine:
    """Tests for graceful handling of malformed log lines."""

    def test_random_text_returns_none(self, parser):
        """Random non-log text must return None."""
        event = parser.parse_line("this is not a log line at all")
        assert event is None

    def test_partial_log_line(self, parser):
        """A truncated log line must return None."""
        event = parser.parse_line('192.168.1.1 - - [10/Oct/2024:13:55:36 +0000] "GET')
        assert event is None

    def test_malformed_does_not_raise(self, parser):
        """Malformed lines must not raise exceptions — they return None."""
        try:
            result = parser.parse_line("}{invalid json{}")
            assert result is None
        except Exception:
            pytest.fail("parse_line raised an exception for malformed input")


# ---------------------------------------------------------------------------
# 4. Missing Fields
# ---------------------------------------------------------------------------
class TestMissingFields:
    """Tests for log lines with missing optional fields."""

    def test_missing_referrer(self, parser):
        """Lines with '-' as referrer must parse with empty referrer."""
        line = (
            '192.168.1.1 - - [10/Oct/2024:13:55:36 +0000] '
            '"GET /page HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
        )
        event = parser.parse_line(line)
        assert event is not None
        assert event.referrer == "-"

    def test_missing_bytes_dash(self, parser):
        """Lines with '-' as byte count must parse with bytes_sent=0."""
        line = (
            '192.168.1.1 - - [10/Oct/2024:13:55:36 +0000] '
            '"GET /page HTTP/1.1" 304 - "-" "Mozilla/5.0"'
        )
        event = parser.parse_line(line)
        assert event is not None
        assert event.bytes_sent == 0


# ---------------------------------------------------------------------------
# 5. IPv6 Address
# ---------------------------------------------------------------------------
class TestIPv6Address:
    """Tests for IPv6 address support in log lines."""

    def test_ipv6_address_parsed(self, parser):
        """IPv6 addresses must be parsed correctly from log lines."""
        line = (
            '::1 - - [10/Oct/2024:13:55:36 +0000] '
            '"GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
        )
        event = parser.parse_line(line)
        assert event is not None
        assert event.ip == "::1"

    def test_full_ipv6_address(self, parser):
        """Full IPv6 addresses (e.g. 2001:db8::1) must be parsed."""
        line = (
            '2001:db8::1 - - [10/Oct/2024:14:00:00 +0000] '
            '"GET /api/status HTTP/1.1" 200 256 "-" "curl/7.68.0"'
        )
        event = parser.parse_line(line)
        assert event is not None
        assert event.ip == "2001:db8::1"


# ---------------------------------------------------------------------------
# 6. Encoded URI
# ---------------------------------------------------------------------------
class TestEncodedURI:
    """Tests for URIs containing URL-encoded characters."""

    def test_encoded_uri_preserved(self, parser):
        """URL-encoded characters in URI must be preserved as-is."""
        line = (
            '192.168.1.1 - - [10/Oct/2024:13:55:36 +0000] '
            '"GET /search?q=hello%20world&lang=en HTTP/1.1" 200 4096 "-" "Mozilla/5.0"'
        )
        event = parser.parse_line(line)
        assert event is not None
        assert "%20" in event.uri

    def test_encoded_special_chars(self, parser):
        """Special encoded characters (%2F, %3D, etc.) must be preserved."""
        line = (
            '10.0.0.1 - - [10/Oct/2024:14:00:00 +0000] '
            '"GET /path%2Fto%2Fresource%3Fkey%3Dvalue HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
        )
        event = parser.parse_line(line)
        assert event is not None
        assert "%2F" in event.uri


# ---------------------------------------------------------------------------
# 7. Large Byte Count
# ---------------------------------------------------------------------------
class TestLargeByteCount:
    """Tests for handling very large byte counts."""

    def test_large_byte_count(self, parser):
        """Byte counts in the millions must parse correctly."""
        line = (
            '192.168.1.1 - - [10/Oct/2024:13:55:36 +0000] '
            '"GET /download/large-file.zip HTTP/1.1" 200 104857600 "-" "Mozilla/5.0"'
        )
        event = parser.parse_line(line)
        assert event is not None
        assert event.bytes_sent == 104857600  # 100 MB

    def test_gigabyte_byte_count(self, parser):
        """Byte counts exceeding 1 GB must parse correctly."""
        line = (
            '192.168.1.1 - - [10/Oct/2024:13:55:36 +0000] '
            '"GET /backup.tar.gz HTTP/1.1" 200 1073741824 "-" "wget/1.21"'
        )
        event = parser.parse_line(line)
        assert event is not None
        assert event.bytes_sent == 1073741824  # 1 GB


# ---------------------------------------------------------------------------
# 8. Empty String
# ---------------------------------------------------------------------------
class TestEmptyString:
    """Tests for empty and whitespace-only inputs."""

    def test_empty_string_returns_none(self, parser):
        """Empty string input must return None."""
        event = parser.parse_line("")
        assert event is None

    def test_whitespace_only_returns_none(self, parser):
        """Whitespace-only input must return None."""
        event = parser.parse_line("   \t  \n  ")
        assert event is None

    def test_newline_only_returns_none(self, parser):
        """Newline-only input must return None."""
        event = parser.parse_line("\n")
        assert event is None


# ---------------------------------------------------------------------------
# 9. Non-HTTP Protocol Line
# ---------------------------------------------------------------------------
class TestNonHTTPProtocol:
    """Tests for log lines that reference non-HTTP protocols."""

    def test_ftp_protocol_not_matched(self, parser):
        """FTP protocol lines should not match HTTP log patterns."""
        line = "192.168.1.1 ftp RETR /etc/passwd 550 0"
        event = parser.parse_line(line)
        assert event is None

    def test_smtp_protocol_not_matched(self, parser):
        """SMTP protocol data should not match HTTP log patterns."""
        line = "SMTP 220 mail.example.com ESMTP Postfix"
        event = parser.parse_line(line)
        assert event is None

    def test_syslog_format_not_matched(self, parser):
        """Syslog-style lines should not match HTTP log patterns."""
        line = "Oct 10 13:55:36 server sshd[12345]: Failed password for root from 192.168.1.1"
        event = parser.parse_line(line)
        assert event is None


# ---------------------------------------------------------------------------
# 10. Throughput Performance
# ---------------------------------------------------------------------------
class TestThroughput:
    """Performance tests — parser must handle ≥5,000 lines/sec."""

    def test_1000_lines_under_200ms(self, parser):
        """1,000 valid log lines must parse in under 0.2 seconds."""
        line = (
            '192.168.1.100 - frank [10/Oct/2024:13:55:36 +0000] '
            '"GET /index.html HTTP/1.1" 200 2326 '
            '"http://www.example.com/" "Mozilla/5.0"'
        )
        lines = [line] * 1000

        start = time.perf_counter()
        events = parser.parse_lines(lines)
        elapsed = time.perf_counter() - start

        assert len(events) == 1000
        assert elapsed < 0.2, f"Parsing 1000 lines took {elapsed:.3f}s (limit: 0.2s)"

    def test_5000_lines_throughput(self, parser):
        """5,000 lines must parse at ≥5,000 lines/sec (CI throughput target)."""
        line = (
            '10.0.0.1 - admin [10/Oct/2024:14:00:00 +0000] '
            '"POST /api/login HTTP/1.1" 401 128 '
            '"-" "curl/7.68.0"'
        )
        lines = [line] * 5000

        start = time.perf_counter()
        events = parser.parse_lines(lines)
        elapsed = time.perf_counter() - start

        rate = 5000 / elapsed
        assert len(events) == 5000
        assert rate >= 5000, f"Throughput {rate:.0f} lines/sec (minimum: 5,000)"

    def test_10000_lines_mixed(self, parser):
        """10,000 lines with mix of valid and invalid must complete efficiently."""
        valid = (
            '192.168.1.1 - - [10/Oct/2024:13:55:36 +0000] '
            '"GET /page HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
        )
        invalid = "not a log line"
        lines = [valid if i % 10 != 0 else invalid for i in range(10000)]

        start = time.perf_counter()
        events = parser.parse_lines(lines)
        elapsed = time.perf_counter() - start

        assert len(events) == 9000  # 90% valid
        assert elapsed < 2.0, f"10k lines took {elapsed:.3f}s (limit: 2.0s)"


# ---------------------------------------------------------------------------
# LogEvent.to_dict() Tests
# ---------------------------------------------------------------------------
class TestLogEventToDict:
    """Tests for the LogEvent.to_dict() serialization method."""

    def test_to_dict_returns_dict(self, parser, sample_apache_log):
        """to_dict() must return a Python dict."""
        event = parser.parse_line(sample_apache_log)
        assert event is not None
        result = event.to_dict()
        assert isinstance(result, dict)

    def test_to_dict_has_all_keys(self, parser, sample_apache_log):
        """to_dict() must include all LogEvent fields."""
        event = parser.parse_line(sample_apache_log)
        assert event is not None
        d = event.to_dict()
        required_keys = {
            "timestamp", "ip", "method", "uri", "status_code",
            "bytes_sent", "user_agent", "referrer", "raw_line",
        }
        assert required_keys.issubset(d.keys())

    def test_to_dict_timestamp_is_iso(self, parser, sample_apache_log):
        """Timestamp in to_dict() must be ISO-formatted string."""
        event = parser.parse_line(sample_apache_log)
        assert event is not None
        d = event.to_dict()
        assert isinstance(d["timestamp"], str)
        assert "2024" in d["timestamp"]


# ---------------------------------------------------------------------------
# Async parse_file() Tests
# ---------------------------------------------------------------------------
class TestParseFile:
    """Tests for the async parse_file() generator."""

    @pytest.mark.asyncio
    async def test_parse_file_reads_events(self, tmp_path):
        """parse_file() must yield LogEvent objects from a file."""
        log_file = tmp_path / "test_access.log"
        log_file.write_text(
            '192.168.1.1 - - [10/Oct/2024:13:55:36 +0000] '
            '"GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n'
            '10.0.0.1 - admin [10/Oct/2024:14:00:00 +0000] '
            '"POST /api/login HTTP/1.1" 401 128 "-" "curl/7.68.0"\n'
        )
        events = []
        async for event in parse_file(str(log_file)):
            events.append(event)

        assert len(events) == 2
        assert events[0].ip == "192.168.1.1"
        assert events[1].ip == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_parse_file_skips_malformed(self, tmp_path):
        """parse_file() must skip malformed lines without stopping."""
        log_file = tmp_path / "mixed.log"
        log_file.write_text(
            '192.168.1.1 - - [10/Oct/2024:13:55:36 +0000] '
            '"GET /page HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n'
            'THIS IS NOT A LOG LINE\n'
            '10.0.0.5 - - [10/Oct/2024:14:00:00 +0000] '
            '"GET /api HTTP/1.1" 200 256 "-" "curl/7.68.0"\n'
        )
        events = []
        async for event in parse_file(str(log_file)):
            events.append(event)

        assert len(events) == 2  # skipped the malformed line

    @pytest.mark.asyncio
    async def test_parse_file_nonexistent(self):
        """parse_file() must handle missing files gracefully."""
        events = []
        async for event in parse_file("/nonexistent/path/access.log"):
            events.append(event)

        assert len(events) == 0

    @pytest.mark.asyncio
    async def test_parse_file_empty(self, tmp_path):
        """parse_file() must handle empty files gracefully."""
        log_file = tmp_path / "empty.log"
        log_file.write_text("")
        events = []
        async for event in parse_file(str(log_file)):
            events.append(event)

        assert len(events) == 0


# ---------------------------------------------------------------------------
# parse_lines() Batch Tests
# ---------------------------------------------------------------------------
class TestParseLines:
    """Tests for the batch parse_lines() method."""

    def test_parse_lines_multiple(self, parser):
        """parse_lines() must process a list of lines and return LogEvents."""
        lines = [
            '192.168.1.1 - - [10/Oct/2024:13:55:36 +0000] '
            '"GET /a HTTP/1.1" 200 100 "-" "Mozilla/5.0"',
            '192.168.1.2 - - [10/Oct/2024:13:55:37 +0000] '
            '"GET /b HTTP/1.1" 200 200 "-" "Mozilla/5.0"',
        ]
        events = parser.parse_lines(lines)
        assert len(events) == 2

    def test_parse_lines_filters_invalid(self, parser):
        """parse_lines() must filter out invalid lines."""
        lines = [
            '192.168.1.1 - - [10/Oct/2024:13:55:36 +0000] '
            '"GET /a HTTP/1.1" 200 100 "-" "Mozilla/5.0"',
            "invalid line",
            "",
        ]
        events = parser.parse_lines(lines)
        assert len(events) == 1

    def test_parse_lines_empty_list(self, parser):
        """parse_lines() with empty list must return empty list."""
        events = parser.parse_lines([])
        assert events == []


# ---------------------------------------------------------------------------
# Helper Function Tests
# ---------------------------------------------------------------------------
class TestHelpers:
    """Tests for parser helper functions."""

    def test_parse_timestamp_valid(self):
        """_parse_timestamp must parse standard Apache/Nginx timestamps."""
        ts = _parse_timestamp("10/Oct/2024:13:55:36 +0000")
        assert ts.year == 2024
        assert ts.month == 10
        assert ts.hour == 13

    def test_parse_timestamp_invalid(self):
        """_parse_timestamp must raise ValueError for invalid timestamps."""
        with pytest.raises(ValueError):
            _parse_timestamp("invalid-timestamp")

    def test_parse_bytes_number(self):
        """_parse_bytes must convert numeric strings to int."""
        assert _parse_bytes("1024") == 1024

    def test_parse_bytes_dash(self):
        """_parse_bytes must return 0 for '-'."""
        assert _parse_bytes("-") == 0

    def test_parse_bytes_invalid(self):
        """_parse_bytes must return 0 for non-numeric strings."""
        assert _parse_bytes("abc") == 0


# ---------------------------------------------------------------------------
# Attack Pattern Log Lines
# ---------------------------------------------------------------------------
class TestAttackLogLines:
    """Tests verifying attack-pattern log lines parse correctly."""

    def test_sqli_log_parses(self, parser, sample_sqli_log):
        """SQL injection log lines must parse — detection is a later module."""
        event = parser.parse_line(sample_sqli_log)
        assert event is not None
        assert "OR" in event.uri or "or" in event.uri

    def test_xss_log_parses(self, parser, sample_xss_log):
        """XSS log lines must parse correctly."""
        event = parser.parse_line(sample_xss_log)
        assert event is not None
        assert "<script>" in event.uri or "script" in event.uri.lower()

    def test_traversal_log_parses(self, parser, sample_traversal_log):
        """Directory traversal log lines must parse correctly."""
        event = parser.parse_line(sample_traversal_log)
        assert event is not None
        assert ".." in event.uri
