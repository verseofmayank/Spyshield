"""Read-only inspection of startup persistence locations.

Windows: HKCU/HKLM Run and RunOnce (+ WOW6432Node), per-user and common Startup folders.
Linux (partial): ~/.config/autostart/*.desktop, ~/.config/systemd/user/*.service, /etc/xdg/autostart.
Nothing is ever written, deleted or changed. Registry access goes through an injectable reader so tests
never touch the real Registry.
"""
from __future__ import annotations

import os
import platform
import socket
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Protocol

from spyshield.collectors.processes import HOST, sha256_file
from spyshield.core.models import Event, utcnow
from spyshield.core.pathutil import extract_target_path, norm
from spyshield.core.redact import redact

WINDOWS_RUN_KEYS = [
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
]


class RegistryReader(Protocol):
    def read_values(self, hive: str, key: str) -> list[tuple[str, str]] | None:
        """[(name, data)] or None if the key is absent/inaccessible."""


class WinRegistryReader:
    """Real, read-only winreg access (KEY_READ only)."""

    def read_values(self, hive: str, key: str) -> list[tuple[str, str]] | None:
        import winreg
        root = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}[hive]
        try:
            with winreg.OpenKey(root, key, 0, winreg.KEY_READ) as k:
                out, i = [], 0
                while True:
                    try:
                        name, data, _t = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    out.append((name, str(data)))
                    i += 1
                return out
        except OSError:
            return None


@dataclass
class FakeRegistry:
    """Test double: {(hive, key): [(name, data)]}"""
    values: dict[tuple[str, str], list[tuple[str, str]]]

    def read_values(self, hive: str, key: str):
        return self.values.get((hive, key))


def startup_folders() -> list[tuple[str, Path]]:
    out = []
    appdata, programdata = os.environ.get("APPDATA"), os.environ.get("PROGRAMDATA")
    if appdata:
        out.append(("StartupFolder:User", Path(appdata) / "Microsoft/Windows/Start Menu/Programs/Startup"))
    if programdata:
        out.append(("StartupFolder:Common", Path(programdata) / "Microsoft/Windows/Start Menu/Programs/StartUp"))
    return out


def _entry(location: str, name: str, command: str, kind: str) -> dict[str, Any]:
    return {"id": f"{location}|{name}", "location": location, "name": name, "command": redact(command), "kind": kind,
            "target_path": extract_target_path(command)}


def snapshot_windows(reader: RegistryReader | None = None, folders: list[tuple[str, Path]] | None = None) -> dict[str, Any]:
    reader = reader or WinRegistryReader()
    entries: dict[str, dict[str, Any]] = {}
    unreadable: list[str] = []
    for hive, key in WINDOWS_RUN_KEYS:
        vals = reader.read_values(hive, key)
        loc = f"{hive}\\{key}"
        if vals is None:
            unreadable.append(loc)
            continue
        for name, data in vals:
            e = _entry(loc, name, data, "registry")
            entries[e["id"]] = e
    for label, folder in (folders if folders is not None else startup_folders()):
        try:
            items = sorted(folder.iterdir()) if folder.is_dir() else []
        except OSError:
            unreadable.append(str(folder))
            continue
        for f in items:
            if f.name.lower() == "desktop.ini" or not f.is_file():
                continue
            e = _entry(f"{label}:{folder}", f.name, str(f), "startup_file")
            e["target_path"] = str(f)
            entries[e["id"]] = e
    return {"platform": "windows", "entries": entries, "unreadable": unreadable}


def snapshot_linux(home: Path | None = None) -> dict[str, Any]:
    home = home or Path.home()
    locs = [("autostart:user", home / ".config/autostart", "*.desktop"), ("systemd:user", home / ".config/systemd/user", "*.service"),
            ("autostart:system", Path("/etc/xdg/autostart"), "*.desktop")]
    entries: dict[str, dict[str, Any]] = {}
    unreadable: list[str] = []
    for label, d, pat in locs:
        try:
            if not d.is_dir():
                continue
            for f in sorted(d.glob(pat)):
                cmd = ""
                try:
                    for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                        if line.startswith("Exec=") or line.startswith("ExecStart="):
                            cmd = line.split("=", 1)[1].strip()
                            break
                except OSError:
                    unreadable.append(str(f))
                e = _entry(f"{label}:{d}", f.name, cmd or str(f), "file")
                entries[e["id"]] = e
        except OSError:
            unreadable.append(str(d))
    return {"platform": "linux", "entries": entries, "unreadable": unreadable}


def supported() -> dict[str, str]:
    sysname = platform.system()
    if sysname == "Windows":
        return {"platform": "windows", "support": "full (Run/RunOnce, Startup folders)"}
    if sysname == "Linux":
        return {"platform": "linux", "support": "partial (XDG autostart + systemd user units; no cron/system services)"}
    return {"platform": sysname.lower(), "support": "unsupported"}


def snapshot(reader: RegistryReader | None = None, folders=None) -> dict[str, Any]:
    sysname = platform.system()
    if sysname == "Windows":
        return snapshot_windows(reader, folders)
    if sysname == "Linux":
        return snapshot_linux()
    return {"platform": sysname.lower(), "entries": {}, "unreadable": [], "unsupported": True}


def target_metadata(path: str | None) -> dict[str, Any]:
    """Metadata about the referenced file (existence, size, SHA-256 if small). Never its contents."""
    if not path:
        return {"exists": None}
    try:
        st = os.stat(path)
    except OSError:
        return {"exists": False}
    digest, reason = sha256_file(path, 50 * 1024 * 1024)
    return {"exists": True, "size": st.st_size, "sha256": digest, "hash_skipped": reason}


def diff(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    b, c = baseline.get("entries", {}), current.get("entries", {})
    added = [c[k] for k in sorted(set(c) - set(b))]
    removed = [b[k] for k in sorted(set(b) - set(c))]
    modified = [{**c[k], "old_command": b[k].get("command")} for k in sorted(set(c) & set(b))
                if c[k].get("command") != b[k].get("command")]
    return {"added": added, "removed": removed, "modified": modified}


def changes_to_events(diff_result: dict[str, list[dict[str, Any]]], *, now: datetime | None = None, host: str = HOST,
                      with_metadata: bool = True) -> list[Event]:
    now = now or utcnow()
    out: list[Event] = []
    for change, items in diff_result.items():
        for e in items:
            meta = target_metadata(e.get("target_path")) if with_metadata and change != "removed" else {}
            out.append(Event(now, "persistence", "persistence_change", host, None, None, None, None, None, None, None,
                             None, None, meta.get("sha256"),
                             {"change": change, "location": e["location"], "entry_name": e["name"], "command": e.get("command"),
                              "old_command": e.get("old_command"), "target_path": e.get("target_path"), "target_meta": meta}))
    return out
