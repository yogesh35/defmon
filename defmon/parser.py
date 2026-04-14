"""DefMon Log Parser — regex-based normalization of raw log lines into structured events.

Supports Apache Combined Log Format and Nginx access logs.
All regex patterns are loaded from config.yaml (log_parser.patterns) so they
can be extended without any code changes.

Complexity: O(n) per line where n is line length.
"""

import re
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional

import aiofiles
from loguru import logger

from defmon.config import get_settings


# ---------------------------------------------------------------------------
# LogEvent Dataclass
# ---------------------------------------------------------------------------
@dataclass
class LogEvent:
    """Structured log event parsed from a raw access log line.

    Fields match the schema defined in models.LogEntry for database persistence.
    """

    timestamp: datetime
    ip: str
    method: str
    uri: str
    status_code: int
    bytes_sent: int
    user_agent: str
    referrer: str
    raw_line: str

    def to_dict(self) -> dict:
        """Convert to dictionary with ISO-formatted timestamp for JSON serialization."""
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        return data


# ---------------------------------------------------------------------------
# Timestamp Parsing Helpers
# ---------------------------------------------------------------------------
# Apache/Nginx timestamp format: 10/Oct/2024:13:55:36 +0000
_TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def _parse_timestamp(raw_ts: str) -> datetime:
    """Parse Apache/Nginx log timestamp string into a datetime object.

    Args:
        raw_ts: Timestamp string like '10/Oct/2024:13:55:36 +0000'.

    Returns:
        Parsed datetime object.

    Raises:
        ValueError: If the timestamp format is invalid.
    """
    return datetime.strptime(raw_ts, _TIMESTAMP_FORMAT)


def _parse_bytes(raw_bytes: str) -> int:
    """Parse byte count from log line, handling '-' as 0.

    Args:
        raw_bytes: Byte count string, or '-' for missing values.

    Returns:
        Integer byte count (0 if missing or invalid).
    """
    if raw_bytes == "-":
        return 0
    try:
        return int(raw_bytes)
    except (ValueError, TypeError):
        return 0


# ---------------------------------------------------------------------------
# Log Parser Class
# ---------------------------------------------------------------------------
class LogParser:
    """Config-driven log parser that normalizes raw log lines into LogEvent objects.

    Loads regex patterns from config.yaml on initialization. Compiles them once
    for efficient repeated matching.
    """

    def __init__(self, settings=None):
        """Initialize parser with compiled regex patterns from config.

        Args:
            settings: Optional Settings instance. Uses global settings if None.
        """
        self._settings = settings or get_settings()
        self._patterns: list[tuple[str, re.Pattern]] = []
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Compile all regex patterns from config.yaml into Pattern objects."""
        raw_patterns = self._settings.log_parser_patterns
        for name, pattern_str in raw_patterns.items():
            try:
                compiled = re.compile(pattern_str)
                self._patterns.append((name, compiled))
                logger.debug(f"Compiled log parser pattern: {name}")
            except re.error as e:
                logger.error(f"Invalid regex pattern '{name}': {e}")

        if not self._patterns:
            logger.warning("No log parser patterns loaded — parser will not match any lines")

    def parse_line(self, line: str) -> Optional[LogEvent]:
        """Parse a single raw log line into a LogEvent.

        Tries each configured pattern in order. Returns the first match.
        Returns None and emits a Loguru warning for malformed lines.

        Args:
            line: Raw log line string.

        Returns:
            LogEvent if parsing succeeds, None otherwise.
        """
        if not line or not line.strip():
            logger.warning("Empty or whitespace-only log line received")
            return None

        stripped = line.strip()

        for pattern_name, pattern in self._patterns:
            match = pattern.match(stripped)
            if match:
                try:
                    groups = match.groupdict()
                    return LogEvent(
                        timestamp=_parse_timestamp(groups["timestamp"]),
                        ip=groups["ip"],
                        method=groups["method"],
                        uri=groups["uri"],
                        status_code=int(groups["status"]),
                        bytes_sent=_parse_bytes(groups["bytes"]),
                        user_agent=groups.get("user_agent", ""),
                        referrer=groups.get("referrer", ""),
                        raw_line=stripped,
                    )
                except (ValueError, KeyError) as e:
                    logger.warning(
                        f"Failed to extract fields from log line with pattern "
                        f"'{pattern_name}': {e}"
                    )
                    return None

        logger.warning(f"No pattern matched log line: {stripped[:120]}...")
        return None

    def parse_lines(self, lines: list[str]) -> list[LogEvent]:
        """Parse multiple log lines, skipping malformed entries.

        Args:
            lines: List of raw log line strings.

        Returns:
            List of successfully parsed LogEvent objects.
        """
        events = []
        for line in lines:
            event = self.parse_line(line)
            if event is not None:
                events.append(event)
        return events


# ---------------------------------------------------------------------------
# Async File Parsing
# ---------------------------------------------------------------------------
async def parse_file(path: str, settings=None) -> "AsyncGenerator[LogEvent, None]":
    """Async generator that streams LogEvent objects from a log file.

    Reads a log file line by line and yields parsed LogEvent objects.
    Malformed lines are silently skipped (warnings logged via Loguru).

    Args:
        path: Path to the log file to parse.
        settings: Optional Settings instance for dependency injection.

    Yields:
        LogEvent objects for each successfully parsed line.
    """
    parser = LogParser(settings=settings)
    try:
        async with aiofiles.open(path, mode="r", encoding="utf-8", errors="replace") as f:
            line_count = 0
            event_count = 0
            async for line in f:
                line_count += 1
                event = parser.parse_line(line)
                if event is not None:
                    event_count += 1
                    yield event

            logger.info(
                f"Parsed {event_count}/{line_count} lines from {path}"
            )
    except FileNotFoundError:
        logger.error(f"Log file not found: {path}")
    except PermissionError:
        logger.error(f"Permission denied reading log file: {path}")
    except Exception as e:
        logger.error(f"Unexpected error reading log file {path}: {e}")


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------
def get_parser(settings=None) -> LogParser:
    """Create and return a LogParser instance.

    Args:
        settings: Optional Settings override for testing.

    Returns:
        Configured LogParser instance.
    """
    return LogParser(settings=settings)
