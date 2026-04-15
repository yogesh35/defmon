#!/usr/bin/env python3
"""Send real access logs to DefMon remote ingest endpoint."""

from __future__ import annotations

import argparse
import json
import random
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from urllib import error, parse, request


MALICIOUS_PATHS = [
    "/login?user=admin' OR '1'='1",
    "/search?q=<script>alert(1)</script>",
    "/api/v1/files?path=../../../../etc/passwd",
    "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
    "/wp-admin/install.php",
    "/phpmyadmin/index.php",
    "/.env",
    "/.git/config",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/api/v1/report?id=1 UNION SELECT username,password FROM users",
]

MALICIOUS_USER_AGENTS = [
    "sqlmap/1.8.5",
    "nikto/2.1.6",
    "WPScan v3.8.25",
    "curl/8.7.1",
    "python-requests/2.31.0",
]

MALICIOUS_SOURCE_IPS = [
    "45.33.32.156",
    "103.224.182.250",
    "178.62.60.166",
    "185.220.101.1",
    "77.247.181.162",
]


def build_ingest_url(api_base: str, sender_id: str, sender_key: str) -> str:
    """Build sender ingest URL with encoded sender credentials."""
    base = api_base.rstrip("/")
    query = parse.urlencode({"sender_id": sender_id, "sender_key": sender_key})
    return f"{base}/api/senders/ingest?{query}"


def _json_request(
    url: str,
    *,
    method: str,
    timeout: int,
    headers: dict[str, str] | None = None,
    json_body: dict | None = None,
    form_body: dict[str, str] | None = None,
):
    """Execute one HTTP request and parse JSON response."""
    if json_body is not None and form_body is not None:
        raise ValueError("Use either json_body or form_body, not both")

    req_headers = dict(headers or {})
    payload: bytes | None = None
    if json_body is not None:
        payload = json.dumps(json_body).encode("utf-8")
        req_headers.setdefault("Content-Type", "application/json")
    elif form_body is not None:
        payload = parse.urlencode(form_body).encode("utf-8")
        req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

    req = request.Request(url, data=payload, headers=req_headers, method=method)
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {url} failed ({exc.code}): {body}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"{method} {url} failed: {exc.reason}") from exc


def login_for_token(api_base: str, username: str, password: str, timeout: int) -> str:
    """Authenticate and return a JWT token."""
    response = _json_request(
        f"{api_base.rstrip('/')}/api/auth/login",
        method="POST",
        timeout=timeout,
        form_body={"username": username, "password": password},
    )
    token = response.get("access_token")
    if not token:
        raise RuntimeError("Login succeeded without access_token in response")
    return token


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _create_sender(
    api_base: str,
    token: str,
    sender_name: str,
    sender_description: str,
    timeout: int,
) -> tuple[str, str]:
    response = _json_request(
        f"{api_base.rstrip('/')}/api/senders",
        method="POST",
        timeout=timeout,
        headers=_auth_headers(token),
        json_body={
            "name": sender_name,
            "description": sender_description,
            "allowed_ip": None,
        },
    )
    sender = response.get("sender", {})
    sender_id = sender.get("id")
    sender_key = response.get("api_key")
    if not sender_id or not sender_key:
        raise RuntimeError("Sender creation did not return sender.id and api_key")
    return sender_id, sender_key


def ensure_sender_credentials(
    api_base: str,
    token: str,
    sender_name: str,
    sender_description: str,
    timeout: int,
) -> tuple[str, str, str]:
    """Create a sender and return (sender_id, sender_key, effective_name)."""
    senders = _json_request(
        f"{api_base.rstrip('/')}/api/senders",
        method="GET",
        timeout=timeout,
        headers=_auth_headers(token),
    )

    existing = next((item for item in senders if item.get("name") == sender_name), None)
    if existing is None:
        sender_id, sender_key = _create_sender(
            api_base=api_base,
            token=token,
            sender_name=sender_name,
            sender_description=sender_description,
            timeout=timeout,
        )
        return sender_id, sender_key, sender_name

    unique_name = f"{sender_name}-{int(time.time())}"
    sender_id, sender_key = _create_sender(
        api_base=api_base,
        token=token,
        sender_name=unique_name,
        sender_description=sender_description,
        timeout=timeout,
    )
    return sender_id, sender_key, unique_name


def collect_real_log_lines(log_paths: list[str], lines_per_file: int) -> list[str]:
    """Collect non-empty tail lines from existing log files."""
    if lines_per_file < 1:
        raise ValueError("lines_per_file must be >= 1")

    collected: list[str] = []
    for raw_path in log_paths:
        path = Path(raw_path)
        if not path.exists() or not path.is_file():
            continue

        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            tail = deque(handle, maxlen=lines_per_file)
            for line in tail:
                cleaned = line.strip()
                if cleaned:
                    collected.append(cleaned)

    return collected


def split_existing_log_paths(log_paths: list[str]) -> tuple[list[str], list[str]]:
    """Return (existing_paths, missing_paths) preserving input order."""
    existing: list[str] = []
    missing: list[str] = []
    for raw_path in log_paths:
        if Path(raw_path).is_file():
            existing.append(raw_path)
        else:
            missing.append(raw_path)
    return existing, missing


def _chunked(items: list[str], chunk_size: int):
    for idx in range(0, len(items), chunk_size):
        yield items[idx : idx + chunk_size]


def _rotating_window(items: list[str], start_idx: int, count: int) -> tuple[list[str], int]:
    """Return up to `count` items starting at `start_idx`, wrapping around."""
    if not items:
        return [], 0
    if count < 1:
        raise ValueError("count must be >= 1")

    size = len(items)
    idx = start_idx % size
    selected: list[str] = []
    for _ in range(min(count, size)):
        selected.append(items[idx])
        idx = (idx + 1) % size
    return selected, idx


def _synthetic_malicious_line(rng: random.Random) -> str:
    method = rng.choice(["GET", "POST"])
    path = rng.choice(MALICIOUS_PATHS)
    status = rng.choice([400, 401, 403, 404, 500])
    size = rng.randint(256, 65535)
    user_agent = rng.choice(MALICIOUS_USER_AGENTS)
    source_ip = rng.choice(MALICIOUS_SOURCE_IPS)
    timestamp = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S %z")
    return (
        f'{source_ip} - - [{timestamp}] "{method} {path} HTTP/1.1" '
        f'{status} {size} "-" "{user_agent}"'
    )


def inject_malicious_lines(
    lines: list[str], malicious_rate: float, rng: random.Random
) -> tuple[list[str], int]:
    """Inject synthetic malicious lines and randomize order."""
    if not lines or malicious_rate <= 0:
        return list(lines), 0

    injected_lines: list[str] = []
    for _ in lines:
        if rng.random() < malicious_rate:
            injected_lines.append(_synthetic_malicious_line(rng))

    if not injected_lines:
        return list(lines), 0

    mixed_lines = [*lines, *injected_lines]
    rng.shuffle(mixed_lines)
    return mixed_lines, len(injected_lines)


def send_batch(
    api_base: str,
    sender_id: str,
    sender_key: str,
    lines: list[str],
    timeout: int,
) -> dict:
    """Send one batch of log lines to DefMon sender ingest API."""
    ingest_url = build_ingest_url(api_base=api_base, sender_id=sender_id, sender_key=sender_key)
    response = _json_request(
        ingest_url,
        method="POST",
        timeout=timeout,
        json_body={"lines": lines},
    )
    return dict(response)


def run_sender(args: argparse.Namespace) -> int:
    existing_log_paths, missing_log_paths = split_existing_log_paths(args.log_path)
    if not existing_log_paths:
        raise RuntimeError(
            "No readable log files found. Checked: {}".format(", ".join(args.log_path))
        )

    token = login_for_token(
        api_base=args.api_base,
        username=args.username,
        password=args.password,
        timeout=args.timeout_seconds,
    )
    sender_id, sender_key, sender_name = ensure_sender_credentials(
        api_base=args.api_base,
        token=token,
        sender_name=args.sender_name,
        sender_description=args.sender_description,
        timeout=args.timeout_seconds,
    )

    if missing_log_paths:
        print("Skipping missing log paths: {}".format(", ".join(missing_log_paths)))

    print(
        f"Log sender ready: name={sender_name} id={sender_id} "
        f"api={args.api_base.rstrip('/')} "
        f"mode={'continuous' if args.continuous else 'one-shot'} "
        f"files={len(existing_log_paths)} "
        f"lines_per_cycle={args.lines_per_cycle if args.continuous else 'all'} "
        f"delay={args.repeat_delay_seconds}s "
        f"malicious_rate={args.malicious_rate}"
    )

    cycle_no = 0
    total_batches = 0
    total_sent = 0
    total_accepted = 0
    total_malicious = 0
    total_normal = 0
    total_rejected = 0
    total_alerts = 0
    total_injected = 0
    rotation_idx = 0
    rng = random.Random(args.random_seed)

    while True:
        lines = collect_real_log_lines(
            log_paths=existing_log_paths,
            lines_per_file=args.lines_per_file,
        )
        if not lines:
            if not args.continuous:
                raise RuntimeError(
                    "No readable log lines found in configured files."
                )
            print(
                "No readable log lines found in configured files; retrying in {}s".format(
                    args.repeat_delay_seconds
                )
            )
            if args.repeat_delay_seconds > 0:
                time.sleep(args.repeat_delay_seconds)
            continue

        lines_to_send = lines
        if args.continuous:
            lines_to_send, rotation_idx = _rotating_window(
                lines,
                start_idx=rotation_idx,
                count=args.lines_per_cycle,
            )
        lines_to_send, injected_count = inject_malicious_lines(
            lines_to_send,
            malicious_rate=args.malicious_rate,
            rng=rng,
        )
        total_injected += injected_count

        cycle_no += 1
        for batch_no, batch in enumerate(_chunked(lines_to_send, args.batch_size), start=1):
            result = send_batch(
                api_base=args.api_base,
                sender_id=sender_id,
                sender_key=sender_key,
                lines=batch,
                timeout=args.timeout_seconds,
            )

            sent = len(batch)
            accepted = int(result.get("accepted_lines", 0))
            malicious = int(result.get("malicious_lines", 0))
            normal = int(result.get("normal_lines", 0))
            rejected = int(result.get("rejected_lines", 0))
            alerts = int(result.get("generated_alerts", 0))

            total_batches += 1
            total_sent += sent
            total_accepted += accepted
            total_malicious += malicious
            total_normal += normal
            total_rejected += rejected
            total_alerts += alerts

            print(
                "cycle={} batch={} sent={} accepted={} rejected={} malicious={} normal={} alerts={} injected={}".format(
                    cycle_no,
                    batch_no,
                    sent,
                    accepted,
                    rejected,
                    malicious,
                    normal,
                    alerts,
                    injected_count,
                )
            )

        if not args.continuous:
            break

        if args.repeat_delay_seconds > 0:
            time.sleep(args.repeat_delay_seconds)

    print(
        "done cycles={} batches={} sent={} accepted={} rejected={} malicious={} normal={} alerts={} injected={}".format(
            cycle_no,
            total_batches,
            total_sent,
            total_accepted,
            total_rejected,
            total_malicious,
            total_normal,
            total_alerts,
            total_injected,
        )
    )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Send real Apache/Nginx access log lines into DefMon "
            "so classification runs on real traffic."
        )
    )
    parser.add_argument("--api-base", default="http://localhost:8000", help="DefMon API base URL")
    parser.add_argument("--username", default="admin", help="DefMon admin username")
    parser.add_argument("--password", default="admin", help="DefMon admin password")
    parser.add_argument(
        "--sender-name",
        default="original-log-source",
        help="Sender name (or name prefix) to create in DefMon",
    )
    parser.add_argument(
        "--sender-description",
        default="Real access log sender",
        help="Sender description stored in DefMon",
    )
    parser.add_argument(
        "--log-path",
        action="append",
        default=[],
        help="Path to a real access log file. Repeat for multiple files.",
    )
    parser.add_argument(
        "--lines-per-file",
        type=int,
        default=300,
        help="How many recent lines to read per file",
    )
    parser.add_argument("--batch-size", type=int, default=100, help="Lines per ingest request")
    parser.add_argument(
        "--continuous",
        action="store_true",
        help="Keep sending in cycles until stopped (Ctrl+C)",
    )
    parser.add_argument(
        "--repeat-delay-seconds",
        type=float,
        default=2.0,
        help="Delay between cycles in continuous mode",
    )
    parser.add_argument(
        "--lines-per-cycle",
        type=int,
        default=5,
        help="Max lines to send per cycle in continuous mode",
    )
    parser.add_argument(
        "--malicious-rate",
        type=float,
        default=0.0,
        help=(
            "Chance (0..1) to inject one synthetic malicious line per selected line "
            "before each send cycle"
        ),
    )
    parser.add_argument(
        "--random-seed",
        type=int,
        default=None,
        help="Optional random seed for deterministic malicious-line injection",
    )
    parser.add_argument("--timeout-seconds", type=int, default=10, help="HTTP timeout in seconds")
    args = parser.parse_args()

    if not args.log_path:
        args.log_path = [
            "data/logs/access.log",
            "data/real_access.log",
            "/var/log/nginx/access.log",
            "/var/log/apache2/access.log",
            "/var/log/httpd/access_log",
        ]
    if args.lines_per_file < 1:
        raise SystemExit("--lines-per-file must be >= 1")
    if args.batch_size < 1:
        raise SystemExit("--batch-size must be >= 1")
    if args.repeat_delay_seconds < 0:
        raise SystemExit("--repeat-delay-seconds must be >= 0")
    if args.lines_per_cycle < 1:
        raise SystemExit("--lines-per-cycle must be >= 1")
    if args.malicious_rate < 0 or args.malicious_rate > 1:
        raise SystemExit("--malicious-rate must be between 0 and 1")

    return args


def main() -> int:
    args = parse_args()
    try:
        return run_sender(args)
    except KeyboardInterrupt:
        print("Log sender stopped by user")
        return 0
    except RuntimeError as exc:
        print(f"Log sender error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
