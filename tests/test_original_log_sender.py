"""Tests for original real-log sender helpers."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "original_log_sender.py"
SPEC = importlib.util.spec_from_file_location("original_log_sender", MODULE_PATH)

if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Unable to load scripts/original_log_sender.py")

original_log_sender = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = original_log_sender
SPEC.loader.exec_module(original_log_sender)


def test_build_ingest_url_encodes_sender_key():
    url = original_log_sender.build_ingest_url(
        "http://localhost:8000/",
        sender_id="snd_abc123",
        sender_key="dmsk_+/=?",
    )
    assert url.startswith("http://localhost:8000/api/senders/ingest?")
    assert "sender_id=snd_abc123" in url
    assert "sender_key=dmsk_%2B%2F%3D%3F" in url


def test_collect_real_log_lines_reads_tail_from_existing_files(tmp_path):
    file_a = tmp_path / "a.log"
    file_b = tmp_path / "b.log"
    file_a.write_text("one\n\n two \nthree\n", encoding="utf-8")
    file_b.write_text("alpha\nbeta\n", encoding="utf-8")

    lines = original_log_sender.collect_real_log_lines(
        [str(file_a), str(file_b)],
        lines_per_file=2,
    )

    assert lines == ["two", "three", "alpha", "beta"]


def test_collect_real_log_lines_skips_missing_paths(tmp_path):
    missing = tmp_path / "missing.log"
    lines = original_log_sender.collect_real_log_lines([str(missing)], lines_per_file=10)
    assert lines == []


def test_collect_real_log_lines_rejects_invalid_tail_size(tmp_path):
    log_file = tmp_path / "access.log"
    log_file.write_text("line\n", encoding="utf-8")

    with pytest.raises(ValueError, match="lines_per_file"):
        original_log_sender.collect_real_log_lines([str(log_file)], lines_per_file=0)


def test_split_existing_log_paths_preserves_order(tmp_path):
    file_a = tmp_path / "a.log"
    file_b = tmp_path / "b.log"
    missing = tmp_path / "missing.log"
    file_a.write_text("a\n", encoding="utf-8")
    file_b.write_text("b\n", encoding="utf-8")

    existing, missing_paths = original_log_sender.split_existing_log_paths(
        [str(file_a), str(missing), str(file_b)]
    )

    assert existing == [str(file_a), str(file_b)]
    assert missing_paths == [str(missing)]


def test_rotating_window_wraps_at_end():
    selected, next_idx = original_log_sender._rotating_window(
        ["a", "b", "c", "d"],
        start_idx=3,
        count=3,
    )
    assert selected == ["d", "a", "b"]
    assert next_idx == 2


def test_rotating_window_caps_to_list_size():
    selected, next_idx = original_log_sender._rotating_window(
        ["x", "y", "z"],
        start_idx=1,
        count=10,
    )
    assert selected == ["y", "z", "x"]
    assert next_idx == 1


def test_parse_args_supports_continuous_mode(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "original_log_sender.py",
            "--continuous",
            "--repeat-delay-seconds",
            "1.5",
            "--lines-per-cycle",
            "3",
            "--log-path",
            "data/real_access.log",
        ],
    )

    args = original_log_sender.parse_args()
    assert args.continuous is True
    assert args.repeat_delay_seconds == pytest.approx(1.5)
    assert args.lines_per_cycle == 3


def test_parse_args_rejects_negative_repeat_delay(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "original_log_sender.py",
            "--repeat-delay-seconds",
            "-1",
            "--log-path",
            "data/real_access.log",
        ],
    )

    with pytest.raises(SystemExit, match="--repeat-delay-seconds must be >= 0"):
        original_log_sender.parse_args()


def test_parse_args_rejects_invalid_lines_per_cycle(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "original_log_sender.py",
            "--lines-per-cycle",
            "0",
            "--log-path",
            "data/real_access.log",
        ],
    )

    with pytest.raises(SystemExit, match="--lines-per-cycle must be >= 1"):
        original_log_sender.parse_args()
