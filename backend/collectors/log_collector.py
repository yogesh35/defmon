"""Log collector — watches log files for new lines and feeds them into
the detection pipeline.

Uses a simple tail-follow approach with async I/O.
"""
import asyncio
import os
from pathlib import Path

from backend.utils.parser import parse_line


class LogCollector:
    """Tail-follow one or more log files and yield NormalizedLog objects."""

    def __init__(self, files: dict[str, str]):
        """files: mapping of source_name -> file_path."""
        self.files = files
        self._offsets: dict[str, int] = {}

    async def tail(self, callback, poll_interval: float = 0.3):
        """Continuously tail all files, calling callback(normalized_log) for each new line."""
        # Initialize offsets
        for name, path in self.files.items():
            if os.path.exists(path):
                self._offsets[name] = os.path.getsize(path)
            else:
                self._offsets[name] = 0
                Path(path).touch()

        while True:
            for name, path in self.files.items():
                if not os.path.exists(path):
                    continue
                size = os.path.getsize(path)
                if size < self._offsets[name]:
                    # File was truncated / rotated
                    self._offsets[name] = 0
                if size > self._offsets[name]:
                    with open(path, "r") as f:
                        f.seek(self._offsets[name])
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            parsed = parse_line(line, source=name)
                            if parsed:
                                await callback(parsed)
                        self._offsets[name] = f.tell()
            await asyncio.sleep(poll_interval)
