"""SQLite investigation database: events, alerts, FIM baselines, persistence snapshots, scans.

Writes happen in transactions; WAL mode; retention pruning; baselines are protected from accidental overwrite.
Only normalised, already-redacted records are stored. No file contents, no passwords.
"""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from typing import Any, Iterable, Iterator

from spyshield.core.models import Alert, Event, iso, utcnow

SCHEMA_VERSION = 1
DEFAULT_DB = Path("spyshield-data") / "spyshield.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY, ts TEXT NOT NULL, command TEXT NOT NULL, host TEXT, notes TEXT);
CREATE TABLE IF NOT EXISTS events (
  event_id TEXT PRIMARY KEY, ts TEXT NOT NULL, source TEXT NOT NULL, kind TEXT NOT NULL, host TEXT,
  proc_key TEXT, pid INTEGER, image TEXT, scan_id INTEGER, body TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
CREATE INDEX IF NOT EXISTS idx_events_proc ON events(proc_key);
CREATE TABLE IF NOT EXISTS alerts (
  alert_id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, severity TEXT NOT NULL, ts TEXT NOT NULL, host TEXT,
  subject TEXT, status TEXT, scan_id INTEGER, body TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);
CREATE TABLE IF NOT EXISTS fim_baselines (root TEXT PRIMARY KEY, created TEXT NOT NULL, host TEXT, file_count INTEGER, skipped INTEGER, options TEXT);
CREATE TABLE IF NOT EXISTS fim_files (
  root TEXT NOT NULL, relpath TEXT NOT NULL, sha256 TEXT, size INTEGER, mtime REAL, mode INTEGER,
  is_symlink INTEGER DEFAULT 0, hash_skipped TEXT, PRIMARY KEY (root, relpath));
CREATE TABLE IF NOT EXISTS persistence_snapshots (id INTEGER PRIMARY KEY, ts TEXT NOT NULL, host TEXT, is_baseline INTEGER NOT NULL, platform TEXT, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""


class StorageError(RuntimeError):
    pass


class BaselineExists(StorageError):
    pass


class Storage:
    def __init__(self, path: str | Path = DEFAULT_DB):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, isolation_level=None)  # autocommit; tx() issues explicit BEGIN/COMMIT
        self.conn.row_factory = sqlite3.Row
        try:
            if self.path != ":memory:":
                self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA foreign_keys=ON")
            ver = self.conn.execute("PRAGMA user_version").fetchone()[0]
            if ver > SCHEMA_VERSION:
                raise StorageError(f"database schema {ver} is newer than this SpyShield ({SCHEMA_VERSION})")
            self.conn.executescript(SCHEMA)
            self.conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        except sqlite3.DatabaseError as exc:
            raise StorageError(f"cannot open database {self.path}: {exc}") from exc

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        try:
            self.conn.execute("BEGIN")
            yield self.conn
            self.conn.execute("COMMIT")
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise

    def close(self) -> None:
        self.conn.close()

    # ---- scans ---------------------------------------------------------------------------
    def start_scan(self, command: str, host: str = "", notes: str = "") -> int:
        with self.tx() as c:
            cur = c.execute("INSERT INTO scans(ts, command, host, notes) VALUES (?,?,?,?)", (iso(utcnow()), command, host, notes))
            return int(cur.lastrowid)

    # ---- events / alerts -----------------------------------------------------------------
    def save_events(self, events: Iterable[Event], scan_id: int | None = None) -> int:
        rows = [(e.event_id, iso(e.ts), e.source, e.kind, e.host, e.proc_key, e.pid, e.image, scan_id,
                 json.dumps(e.to_dict(), default=str)) for e in events]
        with self.tx() as c:
            c.executemany("INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?,?)", rows)
        return len(rows)

    def load_events(self, *, kind: str | None = None, since: str | None = None, limit: int = 100000) -> list[Event]:
        q, args = "SELECT body FROM events WHERE 1=1", []
        if kind:
            q += " AND kind=?"
            args.append(kind)
        if since:
            q += " AND ts>=?"
            args.append(since)
        q += " ORDER BY ts, rowid LIMIT ?"
        args.append(limit)
        return [Event.from_dict(json.loads(r["body"])) for r in self.conn.execute(q, args)]

    def save_alerts(self, alerts: Iterable[Alert], scan_id: int | None = None) -> int:
        n = 0
        with self.tx() as c:
            for a in alerts:
                c.execute("INSERT OR REPLACE INTO alerts VALUES (?,?,?,?,?,?,?,?,?)",
                          (a.alert_id, a.rule_id, a.severity, iso(a.ts), a.host, a.subject, a.status, scan_id,
                           json.dumps(a.to_dict(), default=str)))
                n += 1
        return n

    def load_alerts(self, *, severity: str | None = None, rule_id: str | None = None, limit: int = 1000) -> list[Alert]:
        q, args = "SELECT body FROM alerts WHERE 1=1", []
        if severity:
            q += " AND severity=?"
            args.append(severity)
        if rule_id:
            q += " AND rule_id=?"
            args.append(rule_id)
        q += " ORDER BY ts DESC, rowid DESC LIMIT ?"
        args.append(limit)
        return [Alert.from_dict(json.loads(r["body"])) for r in self.conn.execute(q, args)]

    # ---- FIM baselines -------------------------------------------------------------------
    def has_baseline(self, root: str) -> bool:
        return self.conn.execute("SELECT 1 FROM fim_baselines WHERE root=?", (root,)).fetchone() is not None

    def save_baseline(self, root: str, files: list[dict[str, Any]], *, host: str, skipped: int, options: dict,
                      overwrite: bool = False) -> None:
        if self.has_baseline(root) and not overwrite:
            raise BaselineExists(f"a baseline for {root} already exists; use --force to replace it deliberately")
        with self.tx() as c:
            c.execute("DELETE FROM fim_files WHERE root=?", (root,))
            c.execute("INSERT OR REPLACE INTO fim_baselines VALUES (?,?,?,?,?,?)",
                      (root, iso(utcnow()), host, len(files), skipped, json.dumps(options)))
            c.executemany("INSERT INTO fim_files VALUES (?,?,?,?,?,?,?,?)",
                          [(root, f["relpath"], f.get("sha256"), f.get("size"), f.get("mtime"), f.get("mode"),
                            int(f.get("is_symlink", False)), f.get("hash_skipped")) for f in files])

    def load_baseline(self, root: str) -> tuple[dict[str, dict[str, Any]], dict[str, Any]] | None:
        meta = self.conn.execute("SELECT * FROM fim_baselines WHERE root=?", (root,)).fetchone()
        if not meta:
            return None
        files = {r["relpath"]: dict(r) for r in self.conn.execute("SELECT * FROM fim_files WHERE root=?", (root,))}
        return files, dict(meta)

    # ---- persistence snapshots -----------------------------------------------------------
    def save_persistence(self, snapshot: dict[str, Any], *, host: str, platform: str, baseline: bool = False) -> int:
        with self.tx() as c:
            cur = c.execute("INSERT INTO persistence_snapshots(ts, host, is_baseline, platform, body) VALUES (?,?,?,?,?)",
                            (iso(utcnow()), host, int(baseline), platform, json.dumps(snapshot, default=str)))
            return int(cur.lastrowid)

    def load_persistence_baseline(self, host: str) -> dict[str, Any] | None:
        r = self.conn.execute("SELECT body FROM persistence_snapshots WHERE is_baseline=1 AND host=? ORDER BY id DESC LIMIT 1", (host,)).fetchone()
        return json.loads(r["body"]) if r else None

    # ---- retention / export / clear ------------------------------------------------------
    def prune(self, max_events: int, max_days: float) -> dict[str, int]:
        cutoff = iso(utcnow() - timedelta(days=max_days))
        with self.tx() as c:
            a = c.execute("DELETE FROM events WHERE ts < ?", (cutoff,)).rowcount
            over = c.execute("SELECT COUNT(*) FROM events").fetchone()[0] - max_events
            b = 0
            if over > 0:
                b = c.execute("DELETE FROM events WHERE rowid IN (SELECT rowid FROM events ORDER BY ts, rowid LIMIT ?)", (over,)).rowcount
            d = c.execute("DELETE FROM alerts WHERE ts < ?", (cutoff,)).rowcount
        return {"events_deleted": a + b, "alerts_deleted": d}

    def counts(self) -> dict[str, int]:
        return {t: self.conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                for t in ("events", "alerts", "fim_baselines", "fim_files", "persistence_snapshots", "scans")}

    def export(self) -> dict[str, Any]:
        return {"schema_version": SCHEMA_VERSION, "counts": self.counts(),
                "scans": [dict(r) for r in self.conn.execute("SELECT * FROM scans ORDER BY id")],
                "alerts": [json.loads(r["body"]) for r in self.conn.execute("SELECT body FROM alerts ORDER BY ts")],
                "events": [json.loads(r["body"]) for r in self.conn.execute("SELECT body FROM events ORDER BY ts")]}

    def clear(self, *, include_baselines: bool = False) -> dict[str, int]:
        before = self.counts()
        tables = ["events", "alerts", "scans"]
        if include_baselines:
            tables += ["fim_files", "fim_baselines", "persistence_snapshots"]
        with self.tx() as c:
            for t in tables:
                c.execute(f"DELETE FROM {t}")
        self.conn.execute("VACUUM")
        return {t: before[t] for t in tables}


def default_db_path() -> Path:
    return Path(os.environ.get("SPYSHIELD_DB", DEFAULT_DB))
