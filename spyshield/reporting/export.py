"""Report building: JSON, CSV (alerts), standalone HTML (Jinja2, autoescape, inline CSS, no JavaScript)."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import platform
import re
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Any

from jinja2 import Environment, select_autoescape

from spyshield import AUTHOR, TOOL_NAME, __version__
from spyshield.core.models import SEV_RANK, SEVERITIES, Alert, Event, iso, utcnow
from spyshield.core.redact import redact

SCHEMA_VERSION = "1.0"
MAX_TABLE_ROWS = 300
GENERIC_LIMITATIONS = [
    "SpyShield polls user-mode APIs: processes or connections that start and end between polls are not seen.",
    "Network connections are attributed to processes only when the OS exposes the PID to this user; run privileges affect completeness.",
    "Alerts are observations that need analyst review. They are not verdicts of malware, and SpyShield cannot reliably detect keyloggers.",
    "File integrity results show that a file changed, not who changed it or why.",
    "Sysmon-based rules work only when the relevant Sysmon events (1, 3, 11, 13, 22) are enabled in the Sysmon configuration.",
]


def host_id(host: str, show: bool) -> str:
    if show or host.upper().startswith("DEMO") or host == "localhost":
        return host
    return "host-" + hashlib.sha256(host.encode()).hexdigest()[:10]


def build_report(alerts: list[Alert], events: list[Event], *, title: str = "SpyShield investigation", mode: str = "live",
                 show_hostname: bool = False, extra_limitations: list[str] | None = None, notes: list[str] | None = None,
                 scenario_results: list[dict] | None = None, parse_reports: list[dict] | None = None) -> dict[str, Any]:
    hosts = {e.host for e in events} | {a.host for a in alerts}
    anon = {h: host_id(h, show_hostname) for h in hosts}
    ts = [e.ts for e in events] + [a.ts for a in alerts]
    by_sev = {s: 0 for s in SEVERITIES}
    for a in alerts:
        by_sev[a.severity] += 1
    mitre: dict[str, dict] = {}
    for a in alerts:
        for m in a.mitre:
            mitre.setdefault(m["id"], {"id": m["id"], "name": m.get("name", ""), "rules": set()})["rules"].add(a.rule_id)

    def ev_rows(kind: str) -> list[dict]:
        rows = [e.to_dict() for e in events if e.kind == kind]
        for r in rows:
            r["host"] = anon.get(r["host"], r["host"])
        return rows

    alerts_d = []
    for a in sorted(alerts, key=lambda x: (-SEV_RANK[x.severity], x.ts, x.rule_id)):
        d = a.to_dict()
        d["host"] = anon.get(d["host"], d["host"])
        alerts_d.append(d)
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": __version__, "author": AUTHOR},
        "investigation": {
            "title": title, "mode": mode, "generated_at": iso(utcnow()),
            "timeframe": {"start": iso(min(ts)) if ts else None, "end": iso(max(ts)) if ts else None},
            "hosts": sorted(anon.values()),
            "system": {"os": platform.system(), "os_release": platform.release(), "machine": platform.machine(),
                       "python": platform.python_version()},
            "notes": notes or [],
        },
        "summary": {"events_analyzed": len(events), "alerts": len(alerts), "alerts_by_severity": by_sev,
                    "events_by_kind": {k: sum(e.kind == k for e in events) for k in sorted({e.kind for e in events})}},
        "alerts": alerts_d,
        "observations": {"processes": ev_rows("process_start"), "network": ev_rows("network_connection"),
                         "file_changes": ev_rows("file_change"), "persistence": ev_rows("persistence_change"),
                         "dns": ev_rows("dns_query"), "registry": ev_rows("registry_change")},
        "mitre": [{"id": m["id"], "name": m["name"], "rules": sorted(m["rules"])} for m in sorted(mitre.values(), key=lambda x: x["id"])],
        "evaluation": scenario_results,
        "parse_reports": parse_reports or [],
        "limitations": GENERIC_LIMITATIONS + (extra_limitations or []),
    }


def to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False, default=str)


CSV_FIELDS = ["alert_id", "ts", "severity", "rule_id", "title", "host", "process_name", "process_image", "observation", "confidence",
              "mitre", "status", "suppressed_count"]


def _csv_safe(v: Any) -> str:
    """Neutralise spreadsheet formula injection from untrusted event text."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def to_csv(report: dict[str, Any]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_FIELDS, lineterminator="\n")
    w.writeheader()
    for a in report["alerts"]:
        p = a.get("process", {})
        w.writerow({k: _csv_safe(v) for k, v in {
            "alert_id": a["alert_id"], "ts": a["ts"], "severity": a["severity"], "rule_id": a["rule_id"], "title": a["title"],
            "host": a["host"], "process_name": p.get("name"), "process_image": p.get("image"), "observation": a["observation"],
            "confidence": a["confidence"], "mitre": ";".join(m["id"] for m in a["mitre"]), "status": a["status"],
            "suppressed_count": a["suppressed_count"]}.items()})
    return buf.getvalue()


_env: Environment | None = None


def to_html(report: dict[str, Any]) -> str:
    global _env
    if _env is None:
        tpl = resources.files("spyshield.reporting").joinpath("report.html.j2").read_text(encoding="utf-8")
        _env = Environment(autoescape=select_autoescape(default=True, default_for_string=True), trim_blocks=True, lstrip_blocks=True)
        _env.globals["_tpl"] = tpl
        _env.filters["jsonc"] = lambda v: json.dumps(v, ensure_ascii=False, default=str)
    tpl = _env.from_string(_env.globals["_tpl"])
    return tpl.render(r=report, sevs=list(reversed(SEVERITIES)), max_rows=MAX_TABLE_ROWS)


def write_reports(report: dict[str, Any], formats: list[str], out_dir: str | Path, stem: str = "spyshield-report") -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    fmts = ["json", "csv", "html"] if "all" in formats else formats
    paths = []
    for f in fmts:
        p = out / f"{stem}-{stamp}.{f}"
        p.write_text({"json": to_json, "csv": to_csv, "html": to_html}[f](report), encoding="utf-8", newline="")
        paths.append(p)
    return paths
