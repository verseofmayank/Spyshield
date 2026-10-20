"""File Integrity Monitoring: baseline snapshot, comparison, and optional real-time watch (watchdog).

Safeguards: only explicitly chosen directories; symlinks are recorded but never followed (no loops); exclusions;
file-size and file-count limits; unreadable files counted, not fatal; file contents never stored or reported.
"""
from __future__ import annotations

import fnmatch
import os
import socket
import stat
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from spyshield.collectors.processes import HOST, sha256_file
from spyshield.core.models import Event, utcnow


class FimError(ValueError):
    pass


def resolve_root(path: str) -> str:
    p = Path(path).expanduser()
    if not p.exists():
        raise FimError(f"path does not exist: {path}")
    if not p.is_dir():
        raise FimError(f"not a directory: {path}")
    root = str(p.resolve())
    # Refuse accidental whole-filesystem scans.
    if Path(root).parent == Path(root):
        raise FimError("refusing to monitor a filesystem root; choose a specific directory")
    if len(Path(root).parts) <= 2 and os.name != "nt":
        raise FimError("refusing to monitor a top-level system directory; choose a more specific directory")
    return root


def scan_directory(root: str, *, exclude: list[str] | None = None, max_file_bytes: int = 50 * 1024 * 1024,
                   max_files: int = 20000, hash_files: bool = True) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Walk root (no symlink following) and return ({relpath: record}, stats)."""
    exclude = exclude or []
    files: dict[str, dict[str, Any]] = {}
    stats = {"scanned": 0, "excluded": 0, "unreadable": 0, "symlinks": 0, "hash_skipped": 0, "truncated": False}
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            entries = sorted(os.scandir(d), key=lambda e: e.name)
        except OSError:
            stats["unreadable"] += 1
            continue
        for e in entries:
            rel = os.path.relpath(e.path, root).replace("\\", "/")
            if any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(e.name, pat) for pat in exclude):
                stats["excluded"] += 1
                continue
            try:
                if e.is_symlink():
                    stats["symlinks"] += 1
                    st = e.stat(follow_symlinks=False)
                    files[rel] = {"relpath": rel, "sha256": None, "size": st.st_size, "mtime": st.st_mtime,
                                  "mode": stat.S_IMODE(st.st_mode), "is_symlink": True, "hash_skipped": "symlink (not followed)"}
                    continue
                if e.is_dir(follow_symlinks=False):
                    stack.append(e.path)
                    continue
                if not e.is_file(follow_symlinks=False):
                    continue
                if len(files) >= max_files:
                    stats["truncated"] = True
                    return files, stats
                st = e.stat(follow_symlinks=False)
            except OSError:
                stats["unreadable"] += 1
                continue
            rec: dict[str, Any] = {"relpath": rel, "sha256": None, "size": st.st_size, "mtime": st.st_mtime,
                                   "mode": stat.S_IMODE(st.st_mode), "is_symlink": False, "hash_skipped": None}
            if hash_files:
                digest, reason = sha256_file(e.path, max_file_bytes)
                rec["sha256"], rec["hash_skipped"] = digest, reason
                if reason:
                    stats["hash_skipped"] += 1
                    if reason.startswith("unreadable"):
                        stats["unreadable"] += 1
            files[rel] = rec
            stats["scanned"] += 1
    return files, stats


def compare(baseline: dict[str, dict[str, Any]], current: dict[str, dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """created / modified / deleted. A file whose hash was skipped is compared by size+mtime and labelled so."""
    created = [current[r] for r in sorted(set(current) - set(baseline))]
    deleted = [baseline[r] for r in sorted(set(baseline) - set(current))]
    modified = []
    for r in sorted(set(current) & set(baseline)):
        b, c = baseline[r], current[r]
        if b.get("sha256") and c.get("sha256"):
            if b["sha256"] != c["sha256"]:
                modified.append({**c, "old_sha256": b["sha256"], "basis": "sha256"})
        elif b.get("size") != c.get("size") or abs((b.get("mtime") or 0) - (c.get("mtime") or 0)) > 1e-3:
            modified.append({**c, "old_sha256": b.get("sha256"), "basis": "size/mtime (hash unavailable)"})
        elif bool(b.get("is_symlink")) != bool(c.get("is_symlink")):
            modified.append({**c, "old_sha256": b.get("sha256"), "basis": "type changed"})
    return {"created": created, "modified": modified, "deleted": deleted}


def changes_to_events(root: str, diff: dict[str, list[dict[str, Any]]], *, now: datetime | None = None, host: str = HOST) -> list[Event]:
    now = now or utcnow()
    out: list[Event] = []
    for change, items in diff.items():
        for r in items:
            full = os.path.join(root, r["relpath"])
            out.append(Event(now, "fim", "file_change", host, None, None, None, None, full, None, None, None, None,
                             r.get("sha256"), {"change": change,
                                               "path": full, "relpath": r["relpath"], "root": root, "size": r.get("size"),
                                               "old_sha256": r.get("old_sha256"), "basis": r.get("basis", "baseline comparison")}))
    return out


def watch(root: str, on_event: Callable[[Event], None], *, duration: float, exclude: list[str] | None = None,
          host: str = HOST, max_file_bytes: int = 50 * 1024 * 1024, stop: Callable[[], bool] | None = None) -> dict[str, int]:
    """Real-time watch of one directory for `duration` seconds (watchdog). Returns counts."""
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
    exclude = exclude or []
    counts = {"created": 0, "modified": 0, "deleted": 0, "moved": 0}

    class H(FileSystemEventHandler):
        def _emit(self, change: str, path: str) -> None:
            rel = os.path.relpath(path, root).replace("\\", "/")
            if any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(os.path.basename(path), p) for p in exclude):
                return
            digest = None
            if change != "deleted" and os.path.isfile(path) and not os.path.islink(path):
                digest = sha256_file(path, max_file_bytes)[0]
            counts[change if change in counts else "modified"] += 1
            on_event(Event(utcnow(), "fim", "file_change", host, None, None, None, None, path, None, None, None, None, digest,
                           {"change": "deleted" if change == "deleted" else change, "path": path, "relpath": rel,
                            "root": root, "basis": "watch"}))

        def on_created(self, e):
            if not e.is_directory:
                self._emit("created", e.src_path)

        def on_modified(self, e):
            if not e.is_directory:
                self._emit("modified", e.src_path)

        def on_deleted(self, e):
            if not e.is_directory:
                self._emit("deleted", e.src_path)

        def on_moved(self, e):
            if not e.is_directory:
                self._emit("deleted", e.src_path)
                self._emit("created", e.dest_path)

    obs = Observer()
    obs.schedule(H(), root, recursive=True)
    obs.start()
    end = time.monotonic() + duration
    try:
        while time.monotonic() < end and not (stop and stop()):
            time.sleep(0.2)
    finally:
        obs.stop()
        obs.join(timeout=5)
    return counts
