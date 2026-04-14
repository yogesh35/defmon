#!/usr/bin/env python3
"""Forward real Linux web logs to DefMon remote ingest endpoint.

This script tails one or more log files and pushes new lines in batches to:
    POST /api/senders/ingest?sender_id=<id>&sender_key=<key>

Expected log format: Apache/Nginx combined access log lines.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Dict, List
from urllib import parse, request


def post_batch(api_base: str, sender_id: str, sender_key: str, lines: List[str], timeout: int) -> dict:
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Tail Linux logs and forward to DefMon")
    parser.add_argument("--api-base", required=True, help="DefMon API base URL, e.g. http://10.0.0.20:8000")
    parser.add_argument("--sender-id", required=True, help="Sender ID from DefMon admin")
    parser.add_argument("--sender-key", required=True, help="Sender API key from DefMon admin")
    parser.add_argument(
        "--log-path",
        action="append",
        required=True,
        help="Log file path to tail. Repeat to watch multiple files.",
    )
    parser.add_argument("--batch-size", type=int, default=50, help="Lines per POST request")
    parser.add_argument("--flush-seconds", type=float, default=2.0, help="Max seconds before flushing partial batch")
    parser.add_argument("--poll-seconds", type=float, default=0.5, help="Polling interval for file growth")
    parser.add_argument("--timeout-seconds", type=int, default=10, help="HTTP timeout")
    args = parser.parse_args()

    files: Dict[Path, object] = {}
    for raw in args.log_path:
        path = Path(raw)
        if not path.exists():
            raise SystemExit(f"Log path not found: {path}")
        f = open(path, "r", encoding="utf-8", errors="replace")
        # Start at EOF so we ship only new, real lines from now on.
        f.seek(0, 2)
        files[path] = f

    print(f"Watching {len(files)} log files and forwarding to {args.api_base}")

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
                        api_base=args.api_base,
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
