"""Tests for Linux log forwarder receiver URL resolution."""

from __future__ import annotations

import importlib.util
from argparse import Namespace
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "linux_log_forwarder.py"
SPEC = importlib.util.spec_from_file_location("linux_log_forwarder", MODULE_PATH)

if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Unable to load scripts/linux_log_forwarder.py")

linux_log_forwarder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(linux_log_forwarder)


def _args(**overrides) -> Namespace:
    defaults = {
        "api_base": "",
        "windows_receiver": False,
        "windows_host": "",
        "receiver_port": 8000,
        "receiver_scheme": "http",
    }
    defaults.update(overrides)
    return Namespace(**defaults)


def test_resolve_api_base_from_argument():
    resolved = linux_log_forwarder._resolve_api_base(_args(api_base="http://10.0.0.20:8000/"))
    assert resolved == "http://10.0.0.20:8000"


def test_resolve_api_base_from_env(monkeypatch):
    monkeypatch.setenv("DEFMON_API_BASE", "http://192.168.1.10:8000")
    resolved = linux_log_forwarder._resolve_api_base(_args())
    assert resolved == "http://192.168.1.10:8000"


def test_resolve_windows_receiver_with_explicit_host():
    resolved = linux_log_forwarder._resolve_api_base(
        _args(windows_receiver=True, windows_host="192.168.56.1")
    )
    assert resolved == "http://192.168.56.1:8000"


def test_resolve_windows_receiver_with_detected_host(monkeypatch):
    monkeypatch.setattr(linux_log_forwarder, "_detect_windows_host", lambda: "10.0.75.1")
    resolved = linux_log_forwarder._resolve_api_base(_args(windows_receiver=True))
    assert resolved == "http://10.0.75.1:8000"


def test_resolve_api_base_rejects_conflicting_args():
    with pytest.raises(SystemExit, match="either --api-base/DEFMON_API_BASE or --windows-receiver"):
        linux_log_forwarder._resolve_api_base(
            _args(api_base="http://10.0.0.20:8000", windows_receiver=True)
        )


def test_resolve_api_base_requires_receiver_source():
    with pytest.raises(SystemExit, match="Missing receiver URL"):
        linux_log_forwarder._resolve_api_base(_args())


def test_resolve_windows_receiver_requires_resolved_host(monkeypatch):
    monkeypatch.setattr(linux_log_forwarder, "_detect_windows_host", lambda: None)
    with pytest.raises(SystemExit, match="Could not resolve Windows receiver host"):
        linux_log_forwarder._resolve_api_base(_args(windows_receiver=True))
