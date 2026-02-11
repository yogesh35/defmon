"""Detection rules — each rule is a callable that inspects a NormalizedLog
and returns an alert dict (or None).

Rule registry makes the framework extensible: just decorate with @register_rule.
"""
import re
from typing import Optional
from backend.core.config import MITRE_MAP, SEVERITY_SCORES, SUSPICIOUS_UA

_RULES: list = []


def register_rule(func):
    """Decorator to register a detection rule."""
    _RULES.append(func)
    return func


def get_all_rules():
    return list(_RULES)


def _mitre(rule_id: str) -> dict:
    return MITRE_MAP.get(rule_id, {})


def _make_alert(rule_id: str, rule_name: str, severity: str, source_ip: str,
                description: str, evidence: str) -> dict:
    m = _mitre(rule_id)
    return {
        "rule_id": rule_id,
        "rule_name": rule_name,
        "severity": severity,
        "risk_score": SEVERITY_SCORES.get(severity, 0),
        "source_ip": source_ip,
        "description": description,
        "evidence": evidence[:2000],
        "mitre_tactic": m.get("tactic"),
        "mitre_technique": m.get("technique"),
        "mitre_name": m.get("name"),
    }


# ── SQL Injection ────────────────────────────────────────────────────────────
_SQLI_PATTERNS = [
    r"(?i)(?:union\s+select|select\s+.*\s+from)",
    r"(?i)(?:or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
    r"(?i)(?:drop|alter|insert|update|delete)\s+(?:table|into|from)",
    r"(?i)(?:--|#|/\*)",
    r"(?i)(?:sleep|benchmark|waitfor)\s*\(",
    r"(?i)information_schema",
    r"(?i)(?:char|concat|hex)\s*\(",
    r"(?i)1\s*=\s*1",
    r"(?i)'\s*or\s+'",
]
_SQLI_RE = [re.compile(p) for p in _SQLI_PATTERNS]


@register_rule
def detect_sql_injection(log) -> Optional[dict]:
    """Detect SQL injection patterns in URL or POST body."""
    targets = [log.url or "", log.body or ""]
    for text in targets:
        for pat in _SQLI_RE:
            if pat.search(text):
                return _make_alert(
                    "sql_injection", "SQL Injection Attempt", "critical",
                    log.source_ip,
                    f"SQL injection pattern detected in request to {log.url}",
                    log.raw_line,
                )
    return None


# ── XSS ──────────────────────────────────────────────────────────────────────
_XSS_PATTERNS = [
    r"(?i)<script[\s>]",
    r"(?i)javascript\s*:",
    r"(?i)on(?:error|load|click|mouseover)\s*=",
    r"(?i)alert\s*\(",
    r"(?i)document\.cookie",
    r"(?i)<img[^>]+onerror",
    r"(?i)<iframe",
    r"(?i)eval\s*\(",
]
_XSS_RE = [re.compile(p) for p in _XSS_PATTERNS]


@register_rule
def detect_xss(log) -> Optional[dict]:
    """Detect Cross-Site Scripting attempts."""
    targets = [log.url or "", log.body or ""]
    for text in targets:
        for pat in _XSS_RE:
            if pat.search(text):
                return _make_alert(
                    "xss_attempt", "Cross-Site Scripting (XSS) Attempt", "high",
                    log.source_ip,
                    f"XSS pattern detected in request to {log.url}",
                    log.raw_line,
                )
    return None


# ── Directory Traversal ──────────────────────────────────────────────────────
_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e[/\\]",
    r"(?i)/etc/(?:passwd|shadow|hosts)",
    r"(?i)/proc/self",
    r"(?i)(?:c:|d:)[/\\]",
    r"(?i)/windows/system32",
]
_TRAVERSAL_RE = [re.compile(p) for p in _TRAVERSAL_PATTERNS]


@register_rule
def detect_directory_traversal(log) -> Optional[dict]:
    targets = [log.url or "", log.body or ""]
    for text in targets:
        for pat in _TRAVERSAL_RE:
            if pat.search(text):
                return _make_alert(
                    "directory_traversal", "Directory Traversal Attempt", "high",
                    log.source_ip,
                    f"Path traversal detected: {log.url}",
                    log.raw_line,
                )
    return None


# ── Suspicious User Agent ────────────────────────────────────────────────────
@register_rule
def detect_suspicious_ua(log) -> Optional[dict]:
    ua = (log.user_agent or "").lower()
    for bad in SUSPICIOUS_UA:
        if bad.lower() in ua:
            return _make_alert(
                "suspicious_ua", "Suspicious User-Agent Detected", "low",
                log.source_ip,
                f"Known attack tool UA detected: {log.user_agent}",
                log.raw_line,
            )
    return None
