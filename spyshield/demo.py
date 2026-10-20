"""Offline demonstration and labelled-fixture evaluation. Everything here is SYNTHETIC.

No malware is run and no real system location is modified: process/network events are built from a JSON file,
Registry data comes from an in-memory fake, FIM uses a throw-away temporary directory, and Sysmon data comes from
hand-written XML.
"""
from __future__ import annotations

import json
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

from spyshield.collectors import filesystem, persistence, sysmon
from spyshield.collectors.network import classify_ip
from spyshield.core.config import Config, Watchlist
from spyshield.core.models import Alert, Event, parse_ts
from spyshield.detection.engine import Engine

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS_PATH = ROOT / "samples" / "demo_scenarios.json"
DEMO_HOST = "DEMO-HOST"


@dataclass
class ScenarioResult:
    id: str
    title: str
    label: str                 # benign | should_alert
    expected: list[str]
    got: list[str]
    outcome: str               # TP | FN | TN | FP
    alerts: list[Alert] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def unexpected(self) -> list[str]:
        return sorted(set(self.got) - set(self.expected))


def load_scenarios(path: Path = SCENARIOS_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _events_from_spec(specs: list[dict], base) -> list[Event]:
    keys: dict[str, dict] = {}
    out: list[Event] = []
    for s in specs:
        ts = base + timedelta(seconds=s["t"])
        k = s.get("key")
        if s["kind"] == "process_start":
            keys[k] = s
            parent = keys.get(s.get("parent")) if s.get("parent") else None
            out.append(Event(ts, "synthetic", "process_start", DEMO_HOST, k, s["pid"], s.get("ppid"), s.get("parent"), s["image"], None,
                             parent["image"] if parent else None, s.get("cmd"), s.get("user"), s.get("sha256"),
                             {"initial": False, "synthetic": True}))
        elif s["kind"] == "network_connection":
            proc = keys.get(k, {})
            out.append(Event(ts, "synthetic", "network_connection", DEMO_HOST, k, s["pid"], proc.get("ppid"), None, proc.get("image"), None,
                             None, None, None, None,
                             {"remote_ip": s["remote_ip"], "remote_port": s["remote_port"], "local_port": s.get("local_port"),
                              "remote_class": classify_ip(s["remote_ip"]), "direction": "outbound", "state": "ESTABLISHED",
                              "protocol": "tcp", "synthetic": True}))
        else:
            raise ValueError(f"unknown synthetic event kind {s['kind']!r}")
    return out


def _fake_snapshot(entries: list[dict]) -> dict:
    vals: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for e in entries:
        vals.setdefault((e["hive"], e["key"]), []).append((e["name"], e["data"]))
    return persistence.snapshot_windows(persistence.FakeRegistry(vals), folders=[])


def _fim_events(scn: dict, base) -> tuple[list[Event], list[str]]:
    tmp = Path(tempfile.mkdtemp(prefix="spyshield_demo_"))
    try:
        for name, content in scn["create"].items():
            (tmp / name).write_text(content, encoding="utf-8")
        root = str(tmp.resolve())
        before, _ = filesystem.scan_directory(root)
        for name, content in scn.get("mutate", {}).get("modify", {}).items():
            (tmp / name).write_text(content, encoding="utf-8")
        for name in scn.get("mutate", {}).get("delete", []):
            (tmp / name).unlink()
        after, _ = filesystem.scan_directory(root)
        diff = filesystem.compare(before, after)
        evs = filesystem.changes_to_events(root, diff, now=base + timedelta(seconds=60), host=DEMO_HOST)
        return evs, [f"temporary folder baseline: {len(before)} files; changes: " +
                     ", ".join(f"{k}={len(v)}" for k, v in diff.items())]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def build_scenario_events(scn: dict, base) -> tuple[list[Event], list[str]]:
    kind = scn.get("kind", "events")
    notes: list[str] = []
    if kind == "events":
        return _events_from_spec(scn["events"], base), notes
    if kind == "fim":
        return _fim_events(scn, base)
    if kind in ("persistence", "persistence_exec"):
        diff = persistence.diff(_fake_snapshot(scn["before"]), _fake_snapshot(scn["after"]))
        evs = persistence.changes_to_events(diff, now=base + timedelta(seconds=20), host=DEMO_HOST, with_metadata=False)
        notes.append("persistence diff: " + ", ".join(f"{k}={len(v)}" for k, v in diff.items()) + " (in-memory fake Registry; real Registry untouched)")
        if kind == "persistence_exec":
            evs += _events_from_spec(scn["events"], base)
        return evs, notes
    if kind == "sysmon":
        evs, rep = sysmon.parse_file(ROOT / scn["file"], DEMO_HOST)
        notes.append(f"sysmon parse: {rep.parsed} parsed, {rep.malformed} malformed, {rep.skipped_unsupported} unsupported of {rep.total}")
        return evs, notes
    raise ValueError(f"unknown scenario kind {kind!r}")


def run_scenario(scn: dict, config: Config, watchlist: Watchlist | None, base) -> ScenarioResult:
    events, notes = build_scenario_events(scn, base)
    eng = Engine(config, watchlist, host=DEMO_HOST)
    alerts = eng.process_batch(events)
    got = sorted({a.rule_id for a in alerts})
    expected = list(scn.get("expected_rules", []))
    if scn["label"] == "should_alert":
        outcome = "TP" if set(expected) <= set(got) else "FN"
    else:
        outcome = "TN" if not got else "FP"
    return ScenarioResult(scn["id"], scn["title"], scn["label"], expected, got, outcome, eng.sorted_alerts(), events, notes)


def run_all(config: Config, watchlist: Watchlist | None, path: Path = SCENARIOS_PATH) -> list[ScenarioResult]:
    doc = load_scenarios(path)
    base = parse_ts(doc["base_time"])
    return [run_scenario(s, config, watchlist, base) for s in doc["scenarios"]]


def metrics(results: list[ScenarioResult]) -> dict[str, Any]:
    c = {k: sum(r.outcome == k for r in results) for k in ("TP", "FN", "TN", "FP")}
    prec = c["TP"] / (c["TP"] + c["FP"]) if (c["TP"] + c["FP"]) else None
    rec = c["TP"] / (c["TP"] + c["FN"]) if (c["TP"] + c["FN"]) else None
    return {**c, "scenarios": len(results), "precision": prec, "recall": rec,
            "caveat": "Measured on hand-written synthetic scenarios designed alongside the rules; this is a regression check, NOT a production detection rate."}
