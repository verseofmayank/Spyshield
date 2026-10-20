"""Shared fixtures. All tests are offline, need no admin rights, touch no real persistence locations, run no malware."""
from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spyshield.core.config import Watchlist, load_config, load_watchlist  # noqa: E402
from spyshield.core.models import Event  # noqa: E402
from spyshield.detection.engine import Engine  # noqa: E402

T0 = datetime(2026, 10, 1, 10, 0, 0, tzinfo=timezone.utc)
TEMP_EXE = r"C:\Users\bob\AppData\Local\Temp\x\upd.exe"
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
EXPLORER = r"C:\Windows\explorer.exe"


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


def proc(t, key, pid, image, *, ppid=None, parent=None, parent_image=None, source="synthetic", sha=None, cmd=None, initial=False, **kw) -> Event:
    return Event(at(t), source, "process_start", "h", key, pid, ppid, parent, image, None, parent_image, cmd, None, sha,
                 {"initial": initial, **kw})


def net(t, key, pid, ip, port, *, cls="public", lport=None, source="synthetic", initial=False, direction="outbound", image=None) -> Event:
    return Event(at(t), source, "network_connection", "h", key, pid, None, None, image, None, None, None, None, None,
                 {"remote_ip": ip, "remote_port": port, "remote_class": cls, "direction": direction, "local_port": lport if lport is not None else 40000 + int(t * 10) + port % 7,
                  "state": "ESTABLISHED", "initial": initial})


def persist(t, change, name, command, target, *, location=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", **kw) -> Event:
    return Event(at(t), "persistence", "persistence_change", "h", None, None, None, None, None, None, None, None, None, None,
                 {"change": change, "location": location, "entry_name": name, "command": command, "target_path": target, **kw})


def fimev(t, change, path, **kw) -> Event:
    return Event(at(t), "fim", "file_change", "h", None, None, None, None, path, None, None, None, None, kw.pop("sha", None),
                 {"change": change, "path": path, "basis": "baseline comparison", **kw})


@pytest.fixture(scope="session")
def config():
    return load_config()


@pytest.fixture
def engine(config):
    return Engine(config, Watchlist(), host="h")


@pytest.fixture
def engine_ioc(config):
    return Engine(config, load_watchlist(), host="h")


def rule_ids(alerts):
    return sorted({a.rule_id for a in alerts})
