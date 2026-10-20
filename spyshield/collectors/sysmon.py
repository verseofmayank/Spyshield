"""Sysmon (Microsoft Sysinternals) event parsing: exported XML (offline) and optional live log read.

Supported event IDs: 1 process create, 3 network connect, 5 process terminate, 11 file create,
12 registry object create/delete, 13 registry value set, 22 DNS query. Events with other IDs, or that are
malformed, are counted and skipped, never guessed. Correlation key is the ProcessGuid.
"""
from __future__ import annotations

import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from spyshield.core.models import Event, parse_ts
from spyshield.core.redact import redact

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
SUPPORTED = {1: "process_create", 3: "network_connect", 5: "process_terminate", 11: "file_create",
             12: "registry_object", 13: "registry_value_set", 22: "dns_query"}
MAX_FILE_BYTES = 100 * 1024 * 1024
_FORBIDDEN = re.compile(rb"<!(DOCTYPE|ENTITY)", re.I)


@dataclass
class ParseReport:
    total: int = 0
    parsed: int = 0
    skipped_unsupported: int = 0
    malformed: int = 0
    by_event_id: dict[int, int] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)


def _local(tag: str) -> str:
    return tag.split("}", 1)[-1]


def _data(ev: ET.Element) -> dict[str, str]:
    out = {}
    ed = ev.find(f"{NS}EventData")
    if ed is None:
        ed = ev.find("EventData")
    if ed is not None:
        for d in ed:
            name = d.get("Name")
            if name:
                out[name] = (d.text or "").strip()
    return out


def _find(ev: ET.Element, path: str):
    r = ev.find(f"{NS}{path}")
    return r if r is not None else ev.find(path)


def _int(v: str | None) -> int | None:
    try:
        return int(v) if v not in (None, "") else None
    except ValueError:
        return None


def _extract_events(text: str) -> list[ET.Element]:
    """Accept a <Events> wrapper, a single <Event>, or concatenated <Event> fragments (wevtutil output)."""
    try:
        root = ET.fromstring(text)
        if _local(root.tag) == "Event":
            return [root]
        return [e for e in root.iter() if _local(e.tag) == "Event"]
    except ET.ParseError:
        pass
    events = []
    # Split at each "<Event" start so one broken fragment cannot swallow the valid event after it.
    for frag in re.split(r"(?=<Event[ >])", text)[1:]:
        try:
            events.append(ET.fromstring(frag.strip()))
        except ET.ParseError:
            events.append(ET.Element("Malformed"))
    return events


def normalize(ev: ET.Element, host_default: str = "localhost") -> Event:
    """Convert one <Event> element to a normalised Event. Raises ValueError on missing/invalid mandatory fields."""
    sysel = _find(ev, "System")
    if sysel is None:
        raise ValueError("missing System element")
    eid = _int((_find(sysel, "EventID").text if _find(sysel, "EventID") is not None else None))
    if eid is None:
        raise ValueError("missing or invalid EventID")
    if eid not in SUPPORTED:
        raise KeyError(eid)
    d = _data(ev)
    tc = _find(sysel, "TimeCreated")
    ts_raw = d.get("UtcTime") or (tc.get("SystemTime") if tc is not None else None)
    if not ts_raw:
        raise ValueError("missing timestamp (UtcTime/TimeCreated)")
    try:
        ts = parse_ts(ts_raw)
    except ValueError as exc:
        raise ValueError(f"invalid timestamp {ts_raw!r}") from exc
    comp = _find(sysel, "Computer")
    host = (comp.text.strip() if comp is not None and comp.text else host_default)
    guid = d.get("ProcessGuid") or None
    pid = _int(d.get("ProcessId"))
    image = d.get("Image") or None
    base = dict(host=host, proc_key=guid or (f"{pid}:{ts_raw}" if pid is not None else None), pid=pid, image=image, source="sysmon")
    meta = {"sysmon_event_id": eid, "sysmon_event": SUPPORTED[eid], "process_guid": guid}
    if eid == 1:
        if not (guid and image and pid is not None):
            raise ValueError("process create needs ProcessGuid, ProcessId and Image")
        hashes = {k.lower(): v for k, v in (h.split("=", 1) for h in d.get("Hashes", "").split(",") if "=" in h)}
        return Event(ts, kind="process_start", ppid=_int(d.get("ParentProcessId")), parent_key=d.get("ParentProcessGuid") or None,
                     parent_image=d.get("ParentImage") or None, cmdline=redact(d.get("CommandLine")), user=d.get("User") or None,
                     sha256=hashes.get("sha256"), data={**meta, "initial": False, "integrity_level": d.get("IntegrityLevel"),
                                                       "parent_command_line": redact(d.get("ParentCommandLine"))}, **base)
    if eid == 3:
        rip = d.get("DestinationIp")
        if not rip or not guid:
            raise ValueError("network connect needs ProcessGuid and DestinationIp")
        from spyshield.collectors.network import classify_ip
        return Event(ts, kind="network_connection", user=d.get("User") or None,
                     data={**meta, "remote_ip": rip, "remote_port": _int(d.get("DestinationPort")), "local_ip": d.get("SourceIp"),
                           "local_port": _int(d.get("SourcePort")), "protocol": (d.get("Protocol") or "").lower() or None,
                           "state": "CONNECT", "direction": "outbound" if d.get("Initiated", "true").lower() == "true" else "inbound",
                           "remote_class": classify_ip(rip), "destination_host": d.get("DestinationHostname") or None}, **base)
    if eid == 5:
        if not guid:
            raise ValueError("process terminate needs ProcessGuid")
        return Event(ts, kind="process_end", data=meta, **base)
    if eid == 11:
        path = d.get("TargetFilename")
        if not path:
            raise ValueError("file create needs TargetFilename")
        return Event(ts, kind="file_change", data={**meta, "change": "created", "path": path}, **base)
    if eid in (12, 13):
        key = d.get("TargetObject")
        if not key:
            raise ValueError("registry event needs TargetObject")
        return Event(ts, kind="persistence_change" if _is_run_key(key) else "registry_change",
                     data={**meta, "registry_key": key, "change": {"CreateKey": "added", "SetValue": "modified", "DeleteKey": "removed",
                                                                  "DeleteValue": "removed"}.get(d.get("EventType", ""), "modified"),
                           "event_type": d.get("EventType"), "details": redact(d.get("Details")), "location": "sysmon-registry",
                           "entry_name": key.rsplit("\\", 1)[-1], "is_run_key": _is_run_key(key),
                           "target_path": _target_from_details(d.get("Details"))}, **base)
    if eid == 22:
        q = d.get("QueryName")
        if not q:
            raise ValueError("dns query needs QueryName")
        return Event(ts, kind="dns_query", data={**meta, "dns_query": q, "query_results": d.get("QueryResults"),
                                                          "remote_ip": None, "remote_port": 53, "state": "DNS", "direction": "outbound",
                                                          "remote_class": "n/a"}, **base)
    raise KeyError(eid)


def _is_run_key(key: str) -> bool:
    k = key.lower()
    return "\\currentversion\\run" in k  # Run and RunOnce (+Services variants are not matched on purpose)


def _target_from_details(details: str | None) -> str | None:
    from spyshield.core.pathutil import extract_target_path
    return extract_target_path(details) if details else None


def parse_text(text: str, host_default: str = "localhost") -> tuple[list[Event], ParseReport]:
    if _FORBIDDEN.search(text.encode("utf-8", "ignore")):
        raise ValueError("XML containing DOCTYPE/ENTITY declarations is rejected (XXE / entity-expansion safety)")
    rep = ParseReport()
    events: list[Event] = []
    for el in _extract_events(text):
        rep.total += 1
        try:
            if _local(el.tag) != "Event":
                raise ValueError("malformed XML fragment")
            e = normalize(el, host_default)
        except KeyError as k:
            rep.skipped_unsupported += 1
            rep.by_event_id[int(k.args[0])] = rep.by_event_id.get(int(k.args[0]), 0) + 1
            continue
        except ValueError as exc:
            rep.malformed += 1
            rep.problems.append(f"event #{rep.total}: {exc}")
            continue
        rep.parsed += 1
        rep.by_event_id[e.data["sysmon_event_id"]] = rep.by_event_id.get(e.data["sysmon_event_id"], 0) + 1
        events.append(e)
    return events, rep


def parse_file(path: str | Path, host_default: str = "localhost") -> tuple[list[Event], ParseReport]:
    p = Path(path)
    try:
        if p.stat().st_size > MAX_FILE_BYTES:
            raise ValueError(f"file larger than {MAX_FILE_BYTES // (1024 * 1024)} MB limit")
        text = p.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc.strerror}") from exc
    return parse_text(text, host_default)


def read_live(count: int = 500) -> tuple[list[Event], ParseReport]:
    """Read recent events from the Sysmon operational log with `wevtutil` (documented tool). Windows only.

    Needs permission to read the log (often an elevated prompt) and Sysmon already installed. SpyShield never
    installs or configures Sysmon. UNVERIFIED unless run on a host with Sysmon.
    """
    if sys.platform != "win32":
        raise RuntimeError("live Sysmon reading is only available on Windows")
    try:
        r = subprocess.run(["wevtutil", "qe", "Microsoft-Windows-Sysmon/Operational", "/f:xml", f"/c:{int(count)}", "/rd:false"],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"wevtutil failed: {exc}") from exc
    if r.returncode != 0:
        msg = (r.stderr or r.stdout).strip().splitlines()
        raise RuntimeError("cannot read the Sysmon log (" + (msg[0] if msg else f"exit {r.returncode}") +
                           "). Sysmon may not be installed, or this shell lacks permission.")
    return parse_text(r.stdout)
