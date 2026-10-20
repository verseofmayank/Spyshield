"""Process collector (psutil polling) and process lifecycle tracker.

Identity = (pid, create_time) so a reused PID is a different process. Polling cannot see processes that start
and exit between two polls; Sysmon (event ID 1) is the better source for that.
"""
from __future__ import annotations

import hashlib
import os
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

import psutil

from spyshield.core.models import Event, utcnow
from spyshield.core.redact import redact

HOST = socket.gethostname()


@dataclass
class ProcInfo:
    pid: int
    ppid: int | None
    name: str | None
    exe: str | None
    create_time: float | None
    username: str | None
    status: str | None
    cmdline: str | None
    cpu_seconds: float | None   # cumulative CPU time (a percentage needs two samples)
    rss: int | None
    access_limited: bool = False   # some fields were not accessible

    @property
    def key(self) -> str:
        return f"{self.pid}:{int(self.create_time) if self.create_time else 0}"


def _field(proc: psutil.Process, attr: str, limited: list[bool]) -> Any:
    try:
        return getattr(proc, attr)()
    except (psutil.AccessDenied, psutil.ZombieProcess):
        limited.append(True)
        return None
    except (psutil.NoSuchProcess, OSError):
        return None


def _ppid_map() -> dict[int, int] | None:
    """One-shot PID->PPID map. On Windows psutil's per-process ppid() rebuilds this map every call (~9 ms each),
    which made a full snapshot take ~6 s; building it once is ~40x faster. Falls back to per-process ppid()."""
    try:
        from psutil import _psplatform as pl  # private module, guarded: any failure just uses the slow path
        return dict(pl.ppid_map())
    except Exception:  # noqa: BLE001
        return None


def snapshot(iterator: Callable[[], Iterable[psutil.Process]] = psutil.process_iter) -> list[ProcInfo]:
    """One read-only enumeration. Inaccessible fields become None (flagged), never an exception."""
    out: list[ProcInfo] = []
    ppids = _ppid_map() if iterator is psutil.process_iter else None  # injected iterators (tests) use per-process ppid()
    for p in iterator():
        limited: list[bool] = []
        try:
            with p.oneshot():
                pid = p.pid
                ppid = ppids.get(p.pid) if ppids and p.pid in ppids else _field(p, "ppid", limited)
                name = _field(p, "name", limited)
                exe = _field(p, "exe", limited)
                ct = _field(p, "create_time", limited)
                user = _field(p, "username", limited)
                status = None  # psutil status() costs ~4 ms/process on Windows and adds little detection value
                cmd = _field(p, "cmdline", limited)
                cpu = _field(p, "cpu_times", limited)
                mem = _field(p, "memory_info", limited)
        except psutil.NoSuchProcess:
            continue
        out.append(ProcInfo(pid, ppid, name, exe or None, ct, user,
                            status, redact(" ".join(cmd)) if cmd else None,
                            round(cpu.user + cpu.system, 2) if cpu else None, getattr(mem, "rss", None), bool(limited)))
    return out


def sha256_file(path: str, max_bytes: int) -> tuple[str | None, str | None]:
    """(hex, None) or (None, reason). Never reads files larger than max_bytes or non-regular files."""
    try:
        st = os.stat(path)
        if not os.path.isfile(path):
            return None, "not a regular file"
        if st.st_size > max_bytes:
            return None, f"larger than {max_bytes // (1024 * 1024)} MB limit"
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest(), None
    except OSError as exc:
        return None, f"unreadable ({type(exc).__name__})"


class ProcessTracker:
    """Turns successive snapshots into process_start / process_end events."""

    def __init__(self, *, hash_executables: bool = False, hash_max_bytes: int = 50 * 1024 * 1024, host: str = HOST):
        self.known: dict[str, ProcInfo] = {}
        self.first = True
        self.hash_executables = hash_executables
        self.hash_max_bytes = hash_max_bytes
        self.host = host
        self._hash_cache: dict[str, str | None] = {}
        self.stats = {"snapshots": 0, "access_limited": 0}

    def _hash(self, exe: str | None) -> str | None:
        if not (self.hash_executables and exe):
            return None
        if exe not in self._hash_cache:
            self._hash_cache[exe] = sha256_file(exe, self.hash_max_bytes)[0]
        return self._hash_cache[exe]

    def update(self, procs: list[ProcInfo], now: datetime | None = None) -> list[Event]:
        now = now or utcnow()
        self.stats["snapshots"] += 1
        by_pid_key = {p.pid: p.key for p in procs}
        events: list[Event] = []
        current = {p.key: p for p in procs}
        for key, p in current.items():
            if p.access_limited:
                self.stats["access_limited"] += 1
            if key in self.known:
                old = self.known[key]
                if old.exe and p.exe and old.exe != p.exe:  # image path changed for the same process identity
                    events.append(Event(now, "psutil", "process_start", self.host, key, p.pid, p.ppid,
                                        None, p.exe, p.name, None, p.cmdline, p.username, self._hash(p.exe),
                                        {"initial": False, "image_path_changed_from": old.exe}))
                continue
            ts = datetime.fromtimestamp(p.create_time, timezone.utc) if p.create_time else now
            parent = current.get(by_pid_key.get(p.ppid, "")) if p.ppid is not None else None
            # PID reuse guard: a parent must have been created no later than its child.
            if parent and p.create_time and parent.create_time and parent.create_time > p.create_time:
                parent = None
            events.append(Event(ts, "psutil", "process_start", self.host, key, p.pid, p.ppid,
                                parent.key if parent else None, p.exe, p.name, parent.exe if parent else None,
                                p.cmdline, p.username, self._hash(p.exe),
                                {"initial": self.first, "status": p.status, "cpu_seconds": p.cpu_seconds, "rss": p.rss,
                                 "parent_name": parent.name if parent else None, "access_limited": p.access_limited,
                                 "observed_at": now.isoformat()}))
        for key, p in self.known.items():
            if key not in current:
                events.append(Event(now, "psutil", "process_end", self.host, key, p.pid, p.ppid, None, p.exe, p.name, None))
        self.known = current
        self.first = False
        return events
