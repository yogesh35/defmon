#!/usr/bin/env python3
"""Forward real Linux web logs to DefMon remote ingest endpoint.

This script tails one or more log files and pushes new lines in batches to:
    POST /api/senders/ingest?sender_id=<id>&sender_key=<key>

Expected log format: Apache/Nginx combined access log lines.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import time
from pathlib import Path
from typing import Dict, List
from urllib import parse, request


def post_batch(
    api_base: str,
    sender_id: str,
    sender_key: str,
    lines: List[str],
    timeout: int,
) -> dict:
    query = parse.urlencode({"sender_id": sender_id, "sender_key": sender_key})
    url = f"{api_base.rstrip('/')}/api/senders/ingest?{query}"

    payload = json.dumps({"lines": lines}).encode("utf-8")
    req = request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body)


def _running_in_wsl() -> bool:
    if os.getenv("WSL_DISTRO_NAME"):
        return True

    proc_version = Path("/proc/version")
    if not proc_version.exists():
        return False

    try:
        return "microsoft" in proc_version.read_text(encoding="utf-8", errors="ignore").lower()
    except OSError:
        return False


def _detect_windows_host() -> str | None:
    env_host = os.getenv("DEFMON_WINDOWS_HOST", "").strip()
    if env_host:
        return env_host

    for hostname in ("host.docker.internal", "gateway.docker.internal"):
        try:
            socket.getaddrinfo(hostname, None)
            return hostname
        except OSError:
            continue

    if not _running_in_wsl():
        return None

    resolv_conf = Path("/etc/resolv.conf")
    if not resolv_conf.exists():
        return None

    try:
        for line in resolv_conf.read_text(encoding="utf-8", errors="ignore").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if not stripped.startswith("nameserver"):
                continue
            parts = stripped.split()
            if len(parts) >= 2:
                return parts[1]
    except OSError:
        return None

    return None


def _resolve_api_base(args: argparse.Namespace) -> str:
    explicit_api_base = (args.api_base or os.getenv("DEFMON_API_BASE", "")).strip()

    if explicit_api_base and args.windows_receiver:
        raise SystemExit("Use either --api-base/DEFMON_API_BASE or --windows-receiver, not both.")

    if explicit_api_base:
        return explicit_api_base.rstrip("/")

    if not args.windows_receiver:
        raise SystemExit(
            "Missing receiver URL. Provide --api-base (or DEFMON_API_BASE), "
            "or use --windows-receiver."
        )

    windows_host = (args.windows_host or "").strip() or _detect_windows_host()
    if not windows_host:
        raise SystemExit(
            "Could not resolve Windows receiver host. Set DEFMON_WINDOWS_HOST "
            "or provide --windows-host."
        )

    return f"{args.receiver_scheme}://{windows_host}:{args.receiver_port}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Tail Linux logs and forward to DefMon")
    parser.add_argument(
        "--api-base",
        default="",
        help=(
            "DefMon API base URL, e.g. http://10.0.0.20:8000. "
            "If omitted, DEFMON_API_BASE is used."
        ),
    )
    parser.add_argument(
        "--windows-receiver",
        action="store_true",
        help=(
            "Resolve a Windows-side receiver endpoint using DEFMON_WINDOWS_HOST, "
            "host.docker.internal, or WSL nameserver."
        ),
    )
    parser.add_argument(
        "--windows-host",
        default="",
        help="Override Windows receiver host/IP used by --windows-receiver.",
    )
    parser.add_argument(
        "--receiver-port",
        type=int,
        default=8000,
        help="Receiver port used by --windows-receiver.",
    )
    parser.add_argument(
        "--receiver-scheme",
        choices=("http", "https"),
        default="http",
        help="Receiver URL scheme used by --windows-receiver.",
    )
    parser.add_argument("--sender-id", required=True, help="Sender ID from DefMon admin")
    parser.add_argument("--sender-key", required=True, help="Sender API key from DefMon admin")
    parser.add_argument(
        "--log-path",
        action="append",
        required=True,
        help="Log file path to tail. Repeat to watch multiple files.",
    )
    parser.add_argument("--batch-size", type=int, default=50, help="Lines per POST request")
    parser.add_argument(
        "--flush-seconds",
        type=float,
        default=2.0,
        help="Max seconds before flushing partial batch",
    )
    parser.add_argument(
        "--poll-seconds",
        type=float,
        default=0.5,
        help="Polling interval for file growth",
    )
    parser.add_argument("--timeout-seconds", type=int, default=10, help="HTTP timeout")
    args = parser.parse_args()
    api_base = _resolve_api_base(args)

    files: Dict[Path, object] = {}
    for raw in args.log_path:
        path = Path(raw)
        if not path.exists():
            raise SystemExit(f"Log path not found: {path}")
        f = open(path, "r", encoding="utf-8", errors="replace")
        # Start at EOF so we ship only new, real lines from now on.
        f.seek(0, 2)
        files[path] = f

    print(f"Watching {len(files)} log files and forwarding to {api_base}")

    batch: List[str] = []
    last_flush = time.time()

    try:
        while True:
            for _, handle in files.items():
                while True:
                    line = handle.readline()
                    if not line:
                        break
                    stripped = line.strip()
                    if stripped:
                        batch.append(stripped)

            now = time.time()
            should_flush = len(batch) >= args.batch_size or (
                batch and (now - last_flush) >= args.flush_seconds
            )

            if should_flush:
                try:
                    result = post_batch(
                        api_base=api_base,
                        sender_id=args.sender_id,
                        sender_key=args.sender_key,
                        lines=batch,
                        timeout=args.timeout_seconds,
                    )
                    print(
                        "sent={} accepted={} rejected={} malicious={} normal={}".format(
                            len(batch),
                            result.get("accepted_lines", 0),
                            result.get("rejected_lines", 0),
                            result.get("malicious_lines", 0),
                            result.get("normal_lines", 0),
                        )
                    )
                except Exception as exc:
                    print(f"send failed for {len(batch)} lines: {exc}")
                finally:
                    batch = []
                    last_flush = now

            time.sleep(args.poll_seconds)
    except KeyboardInterrupt:
        print("Stopped by user")
    finally:
        for f in files.values():
            try:
                f.close()
            except Exception:
                pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
