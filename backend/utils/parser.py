"""Log parser and normalizer — handles Apache/Nginx combined, auth, and app logs."""
import re
from datetime import datetime
from typing import Optional

# Apache / Nginx combined log format
# 192.168.1.1 - - [08/Feb/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
_COMBINED_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>.+?) HTTP/\S+" '
    r'(?P<status>\d{3}) \S+ '
    r'"[^"]*" '
    r'"(?P<ua>[^"]*)"'
)

# Auth log (simplified)
# Feb  8 10:00:00 server sshd[1234]: Failed password for admin from 10.0.0.1 port 22 ssh2
_AUTH_RE = re.compile(
    r'(?P<ts>\w+ +\d+ \d+:\d+:\d+) \S+ \S+: '
    r'(?P<msg>.*?from (?P<ip>\d+\.\d+\.\d+\.\d+).*)'
)

# Application log (JSON-ish)
# 2026-02-08T10:00:00 [ERROR] ip=10.0.0.1 method=POST url=/api/login body="username=admin&password=test"
_APP_RE = re.compile(
    r'(?P<ts>\S+) \[(?P<level>\w+)\] '
    r'ip=(?P<ip>\S+) method=(?P<method>\S+) '
    r'url=(?P<url>\S+)(?: body="(?P<body>[^"]*)")?'
)

_TS_FORMATS = [
    "%d/%b/%Y:%H:%M:%S %z",   # Apache
    "%Y-%m-%dT%H:%M:%S",       # ISO (no tz)
    "%Y-%m-%dT%H:%M:%S%z",     # ISO with tz
]


def _parse_ts(raw: str) -> datetime:
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(raw.strip(), fmt)
        except ValueError:
            continue
    return datetime.utcnow()


class NormalizedLog:
    """Unified representation of any log event."""
    __slots__ = (
        "timestamp", "source_ip", "method", "url", "status_code",
        "user_agent", "body", "log_source", "raw_line",
    )

    def __init__(self, **kwargs):
        for slot in self.__slots__:
            setattr(self, slot, kwargs.get(slot))

    def to_dict(self):
        return {s: getattr(self, s) for s in self.__slots__}


def parse_access_log(line: str) -> Optional[NormalizedLog]:
    """Parse Apache/Nginx combined format."""
    m = _COMBINED_RE.match(line)
    if not m:
        return None
    return NormalizedLog(
        timestamp=_parse_ts(m.group("ts")),
        source_ip=m.group("ip"),
        method=m.group("method"),
        url=m.group("url"),
        status_code=int(m.group("status")),
        user_agent=m.group("ua"),
        body=None,
        log_source="access",
        raw_line=line.strip(),
    )


def parse_auth_log(line: str) -> Optional[NormalizedLog]:
    """Parse syslog-style auth log."""
    m = _AUTH_RE.match(line)
    if not m:
        return None
    now = datetime.utcnow()
    try:
        ts = datetime.strptime(m.group("ts"), "%b %d %H:%M:%S").replace(year=now.year)
    except ValueError:
        ts = now

    msg = m.group("msg")
    status = 401 if "Failed" in msg else 200

    return NormalizedLog(
        timestamp=ts,
        source_ip=m.group("ip"),
        method="AUTH",
        url="/ssh",
        status_code=status,
        user_agent="sshd",
        body=msg,
        log_source="auth",
        raw_line=line.strip(),
    )


def parse_app_log(line: str) -> Optional[NormalizedLog]:
    """Parse application log."""
    m = _APP_RE.match(line)
    if not m:
        return None
    return NormalizedLog(
        timestamp=_parse_ts(m.group("ts")),
        source_ip=m.group("ip"),
        method=m.group("method"),
        url=m.group("url"),
        status_code=0,
        user_agent="app",
        body=m.group("body") or "",
        log_source="app",
        raw_line=line.strip(),
    )


def parse_line(line: str, source: str = "access") -> Optional[NormalizedLog]:
    """Auto-detect and parse a log line."""
    parsers = {
        "access": parse_access_log,
        "auth":   parse_auth_log,
        "app":    parse_app_log,
    }
    parser = parsers.get(source, parse_access_log)
    result = parser(line)
    if result is None and source != "access":
        result = parse_access_log(line)
    return result
