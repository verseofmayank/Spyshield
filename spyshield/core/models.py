"""Normalised event and alert schema shared by every collector, the engine, storage and reports."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

SEVERITIES = ["info", "low", "medium", "high"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

KINDS = {"process_start", "process_end", "network_connection", "file_change", "persistence_change", "registry_change", "dns_query"}


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def to_utc(dt: datetime) -> datetime:
    """Return an aware UTC datetime (naive input is assumed to already be UTC)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_ts(value: Any) -> datetime:
    """Parse ISO-8601 / Sysmon 'YYYY-MM-DD HH:MM:SS.fff' / epoch seconds into aware UTC."""
    if isinstance(value, datetime):
        return to_utc(value)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), timezone.utc)
    s = str(value).strip().replace("Z", "+00:00")
    if " " in s and "T" not in s:
        s = s.replace(" ", "T", 1)
    return to_utc(datetime.fromisoformat(s))


def iso(dt: datetime) -> str:
    return to_utc(dt).isoformat().replace("+00:00", "Z")


@dataclass
class Event:
    """One normalised observation.

    proc_key is the stable process identity: the Sysmon ProcessGuid when available, otherwise
    "<pid>:<create-time-epoch>" so a reused PID never collides with an earlier process.
    """
    ts: datetime
    source: str            # psutil | sysmon | fim | persistence | synthetic
    kind: str              # one of KINDS
    host: str = "localhost"
    proc_key: str | None = None
    pid: int | None = None
    ppid: int | None = None
    parent_key: str | None = None
    image: str | None = None
    name: str | None = None
    parent_image: str | None = None
    cmdline: str | None = None   # already redacted
    user: str | None = None
    sha256: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    event_id: str = ""
    seq: int = 0                 # arrival order, tie-breaker for equal timestamps

    def __post_init__(self) -> None:
        self.ts = to_utc(self.ts)
        if self.image and not self.name:
            self.name = self.image.replace("\\", "/").rsplit("/", 1)[-1]
        if not self.event_id:
            raw = json.dumps([self.source, self.kind, self.proc_key, iso(self.ts), self.image, self.data],
                             sort_keys=True, default=str)
            self.event_id = hashlib.sha1(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {"event_id": self.event_id, "ts": iso(self.ts), "source": self.source, "kind": self.kind,
                "host": self.host, "proc_key": self.proc_key, "pid": self.pid, "ppid": self.ppid,
                "parent_key": self.parent_key, "image": self.image, "name": self.name,
                "parent_image": self.parent_image, "cmdline": self.cmdline, "user": self.user,
                "sha256": self.sha256, "data": self.data}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Event":
        d = dict(d)
        d["ts"] = parse_ts(d["ts"])
        d.setdefault("data", {})
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    def brief(self) -> dict[str, Any]:
        """Compact form used as alert evidence."""
        out = {"ts": iso(self.ts), "source": self.source, "kind": self.kind, "pid": self.pid, "image": self.image}
        for k in ("remote_ip", "remote_port", "state", "path", "change", "location", "entry_name", "target_path",
                  "protocol", "registry_key"):
            if k in self.data:
                out[k] = self.data[k]
        if self.sha256:
            out["sha256"] = self.sha256
        return out


@dataclass
class Alert:
    alert_id: str
    rule_id: str
    title: str
    severity: str
    ts: datetime
    host: str
    observation: str
    subject: str
    process: dict[str, Any] = field(default_factory=dict)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    conditions_met: list[str] = field(default_factory=list)
    confidence: str = "low"
    limitations: str = ""
    mitre: list[dict[str, str]] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    investigation_steps: list[str] = field(default_factory=list)
    status: str = "requires analyst review"
    suppressed_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"alert_id": self.alert_id, "rule_id": self.rule_id, "title": self.title, "severity": self.severity,
                "ts": iso(self.ts), "host": self.host, "observation": self.observation, "subject": self.subject,
                "process": self.process, "evidence": self.evidence, "conditions_met": self.conditions_met,
                "confidence": self.confidence, "limitations": self.limitations, "mitre": self.mitre,
                "false_positives": self.false_positives, "investigation_steps": self.investigation_steps,
                "status": self.status, "suppressed_count": self.suppressed_count}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Alert":
        d = dict(d)
        d["ts"] = parse_ts(d["ts"])
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})
