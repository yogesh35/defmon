"""DefMon Log Collector — async file watcher that ingests new log lines in real time.

Uses the watchfiles library (free, cross-platform) to detect changes to
log files and feeds new lines to the parser for processing.

Usage:
    collector = LogCollector(log_paths=["/var/log/apache2/access.log"])
    async for event in collector.watch():
        # event is a LogEvent ready for detection engine
        await detection_engine.analyze(event)
"""

import asyncio
from pathlib import Path
from typing import AsyncGenerator, Callable, Optional

from loguru import logger
from watchfiles import awatch, Change

from defmon.config import get_settings
from defmon.parser import LogParser, LogEvent


class LogCollector:
    """Async log file collector that watches for new lines and parses them.

    Maintains file position state so only new lines appended after startup
    (or since last read) are processed. Supports watching multiple log files.
    """

    def __init__(
        self,
        log_paths: list[str] | None = None,
        settings=None,
        callback: Optional[Callable] = None,
    ):
        """Initialize the log collector.

        Args:
            log_paths: List of log file paths to watch. Defaults to configured real log sources.
            settings: Optional Settings instance for dependency injection.
            callback: Optional async callback invoked for each parsed LogEvent.
        """
        self._settings = settings or get_settings()
        self._parser = LogParser(settings=self._settings)
        self._callback = callback
        self._running = False

        # Prefer configured real log sources.
        if log_paths is None:
            log_paths = list(self._settings.log_sources or [])
            if not log_paths:
                log_paths = [
                    "/var/log/nginx/access.log",
                    "/var/log/apache2/access.log",
                    "/var/log/httpd/access_log",
                    "/app/data/real_access.log",
                ]

        self._log_paths = [Path(p) for p in log_paths]

        # Track file positions for incremental reading
        self._file_positions: dict[str, int] = {}

        # Statistics
        self._total_lines_read = 0
        self._total_events_parsed = 0

    async def _read_new_lines(self, file_path: Path) -> list[str]:
        """Read new lines from a file since last known position.

        Args:
            file_path: Path to the log file.

        Returns:
            List of new lines appended since last read.
        """
        path_str = str(file_path)
        try:
            # Get current position (default to 0 for first read)
            last_pos = self._file_positions.get(path_str, 0)

            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(last_pos)
                new_lines = f.readlines()
                self._file_positions[path_str] = f.tell()

            return new_lines

        except FileNotFoundError:
            logger.warning(f"Watched log file not found: {path_str}")
            return []
        except PermissionError:
            logger.error(f"Permission denied reading: {path_str}")
            return []
        except Exception as e:
            logger.error(f"Error reading {path_str}: {e}")
            return []

    async def _process_lines(self, lines: list[str]) -> list[LogEvent]:
        """Parse a batch of raw log lines into LogEvent objects.

        Args:
            lines: Raw log lines to parse.

        Returns:
            List of successfully parsed LogEvent objects.
        """
        events = []
        for line in lines:
            event = self._parser.parse_line(line)
            if event is not None:
                events.append(event)
                self._total_events_parsed += 1

                # Invoke callback if registered
                if self._callback is not None:
                    try:
                        await self._callback(event)
                    except Exception as e:
                        logger.error(f"Callback error for event: {e}")

            self._total_lines_read += 1

        return events

    async def ingest_existing(self) -> list[LogEvent]:
        """Read and parse all existing content from watched log files.

        Call this once at startup to process any log data that was written
        before the collector started watching.

        Returns:
            List of all parsed LogEvent objects from existing file content.
        """
        all_events = []
        for path in self._log_paths:
            if path.exists():
                new_lines = await self._read_new_lines(path)
                events = await self._process_lines(new_lines)
                all_events.extend(events)
                logger.info(
                    f"Ingested {len(events)} events from existing file: {path}"
                )
            else:
                logger.warning(f"Log file does not exist yet: {path}")

        return all_events

    async def watch(self) -> AsyncGenerator[LogEvent, None]:
        """Async generator that yields LogEvent objects as new lines are written.

        Uses watchfiles.awatch for efficient cross-platform file monitoring.
        Yields events in real-time as log files are modified.

        Yields:
            LogEvent objects for each new log line detected.
        """
        self._running = True

        # Resolve directories to watch (parent dirs of log files)
        watch_dirs = set()
        for path in self._log_paths:
            parent = path.parent if path.parent.exists() else Path(".")
            watch_dirs.add(str(parent.resolve()))

        logger.info(
            f"🔍 Log collector watching {len(self._log_paths)} file(s) "
            f"in {len(watch_dirs)} directory(ies)"
        )

        try:
            async for changes in awatch(*watch_dirs):
                if not self._running:
                    break

                for change_type, changed_path in changes:
                    # Only process modifications to our tracked files
                    changed_path = Path(changed_path)
                    if change_type == Change.modified and changed_path in [
                        p.resolve() for p in self._log_paths
                    ]:
                        new_lines = await self._read_new_lines(changed_path)
                        if new_lines:
                            events = await self._process_lines(new_lines)
                            for event in events:
                                yield event

        except asyncio.CancelledError:
            logger.info("Log collector watch cancelled")
        except Exception as e:
            logger.error(f"Log collector watch error: {e}")
        finally:
            self._running = False
            logger.info(
                f"Log collector stopped. "
                f"Total: {self._total_lines_read} lines read, "
                f"{self._total_events_parsed} events parsed"
            )

    def stop(self) -> None:
        """Signal the collector to stop watching."""
        self._running = False
        logger.info("Log collector stop requested")

    @property
    def stats(self) -> dict:
        """Return collector statistics."""
        return {
            "total_lines_read": self._total_lines_read,
            "total_events_parsed": self._total_events_parsed,
            "watched_files": [str(p) for p in self._log_paths],
            "running": self._running,
        }
