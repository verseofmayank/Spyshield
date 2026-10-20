"""Rule evaluators. Each takes (engine, rule, event) and returns a list of RuleHit.

Evaluators contain *logic* (paths, ancestry, thresholds, time-window correlation); they never decide on
process names containing words like 'spy' or 'record'.
"""
from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING, Callable

from spyshield.core.config import Rule
from spyshield.core.models import Event, iso
from spyshield.core.pathutil import basename, extension, matches_any, norm

if TYPE_CHECKING:  # pragma: no cover
    from spyshield.detection.engine import Engine


@dataclass
class RuleHit:
    subject: str
    observation: str
    anchor: Event
    evidence: list[Event] = field(default_factory=list)
    conditions: list[str] = field(default_factory=list)
    severity: str | None = None          # override rule severity
    mitre: list[dict] | None = None      # None = use the rule's mapping, [] = suppress
    extra_limitations: str = ""
    process_event: Event | None = None   # event whose process fields describe the alert subject


def _suspicious(engine: "Engine", image: str | None) -> str | None:
    """Matching suspicious-path pattern, unless the image is allowlisted."""
    if not image:
        return None
    if matches_any(image, engine.config.lists["allowlist_image_patterns"]):
        return None
    return matches_any(image, engine.config.lists["suspicious_path_patterns"])


def _is_public(ev: Event) -> bool:
    return ev.data.get("remote_class") == "public"


# ---- SHIELD-001 ------------------------------------------------------------------------------
def exec_location(engine, rule: Rule, ev: Event) -> list[RuleHit]:
    if ev.kind != "process_start" or not ev.image:
        return []
    pat = _suspicious(engine, ev.image)
    if not pat:
        return []
    exts = [e.lower() for e in rule.params.get("executable_extensions", [])]
    ext = extension(ev.image)
    if exts and ext and ext not in exts:
        return []
    conds = [f"image path matches configured suspicious location '{pat}'", f"executable type '{ext or 'none'}'"]
    sev = None
    parent = engine.history.parent_of(ev)
    parent_name = basename(ev.parent_image or (parent.image if parent else None))
    if parent_name and parent_name in [p.lower() for p in rule.params.get("escalate_if_parent_in", [])]:
        conds.append(f"parent process '{parent_name}' is on the escalation list (document/script host)")
        sev = "medium"
    else:
        conds.append("no additional corroborating condition (location only)")
    return [RuleHit(ev.proc_key or ev.image, f"Process '{ev.name}' started from a configured temporary/user-writable location: {ev.image}",
                    ev, [ev], conds, sev, process_event=ev)]


# ---- SHIELD-002 ------------------------------------------------------------------------------
def parent_child(engine, rule: Rule, ev: Event) -> list[RuleHit]:
    if ev.kind != "process_start" or not ev.image:
        return []
    parent = engine.history.parent_of(ev)
    parent_img = ev.parent_image or (parent.image if parent else None)
    pname, cname = basename(parent_img), basename(ev.image)
    if not pname:
        return []
    for pair in rule.params["pairs"]:
        if pname in [x.lower() for x in pair["parent"]] and cname in [x.lower() for x in pair["child"]]:
            chain = [basename(e.image) for e in reversed(engine.history.lineage(ev)) if e.image]
            ev_list = ([parent] if parent else []) + [ev]
            return [RuleHit(ev.proc_key or ev.image, f"'{pname}' launched '{cname}' (configured unusual parent-child pair)", ev, ev_list,
                            [f"parent '{pname}' is in configured parent list", f"child '{cname}' is in configured child list",
                             "lineage: " + " -> ".join(chain + [cname]) if chain else f"lineage: {pname} -> {cname}"], process_event=ev)]
    return []


# ---- SHIELD-003 ------------------------------------------------------------------------------
_WIN_PERSIST_LOCS = ("hkcu", "hklm", "startupfolder", "sysmon-registry")


def persistence_change(engine, rule: Rule, ev: Event) -> list[RuleHit]:
    if ev.kind != "persistence_change" or ev.data.get("change") not in rule.params.get("changes", ["added", "modified"]):
        return []
    d = ev.data
    target = d.get("target_path")
    conds = [f"entry {d['change']} compared with the stored baseline" if ev.source != "sysmon" else f"Sysmon registry event ({d.get('event_type')})"]
    sev = None
    if rule.params.get("escalate_if_target_in_suspicious_path") and target and _suspicious(engine, target):
        conds.append(f"referenced path is in a configured suspicious location: {target}")
        sev = "medium"
    meta = d.get("target_meta") or {}
    if meta.get("exists") is False:
        conds.append("referenced file does not exist on disk at observation time")
    elif meta.get("exists"):
        conds.append(f"referenced file exists (size {meta.get('size')} bytes)")
    loc = str(d.get("location", "")).lower()
    mitre = None if loc.startswith(_WIN_PERSIST_LOCS) and (d.get("is_run_key", True)) else []
    return [RuleHit(f"{d.get('location')}|{d.get('entry_name')}|{d['change']}",
                    f"Startup entry '{d.get('entry_name')}' {d['change']} at {d.get('location')}: {d.get('command') or d.get('details') or target}",
                    ev, [ev], conds, sev, mitre)]


# ---- SHIELD-004 ------------------------------------------------------------------------------
def proc_net_correlation(engine, rule: Rule, ev: Event) -> list[RuleHit]:
    if ev.kind != "network_connection" or not ev.proc_key or ev.data.get("direction") != "outbound" or ev.data.get("remote_ip") is None:
        return []
    if rule.params.get("public_only", True) and not _is_public(ev):
        return []
    start = engine.history.start_of(ev.proc_key)
    if not start:
        return []
    win = rule.params["window_seconds"]
    if not (timedelta(0) <= ev.ts - start.ts <= timedelta(seconds=win)):
        return []
    pat = _suspicious(engine, start.image)
    if not pat:
        return []
    delta = int((ev.ts - start.ts).total_seconds())
    return [RuleHit(ev.proc_key, f"'{start.name}' started from a suspicious location and {delta}s later connected to "
                                 f"{ev.data['remote_ip']}:{ev.data.get('remote_port')}", start, [start, ev],
                    [f"image path matches configured suspicious location '{pat}'", f"process was created {delta}s before the connection (window {win}s)",
                     f"outbound connection to {ev.data.get('remote_class')} address"], process_event=start)]


# ---- SHIELD-005 ------------------------------------------------------------------------------
def fim_change(engine, rule: Rule, ev: Event) -> list[RuleHit]:
    if ev.kind != "file_change" or ev.source != "fim" or ev.data.get("change") not in rule.params.get("changes", ["modified"]):
        return []
    path = ev.data.get("path")
    sev = rule.params.get("default_severity", "low")
    why = "default severity for monitored paths"
    for ps in rule.params.get("path_severity", []) or []:
        if matches_any(path, [ps["prefix"]]):
            sev, why = ps["severity"], f"path matches configured severity pattern '{ps['prefix']}'"
            break
    conds = [f"file {ev.data['change']} compared with the baseline ({ev.data.get('basis')})", why]
    if ev.data.get("old_sha256") and ev.sha256:
        conds.append(f"SHA-256 changed {ev.data['old_sha256'][:12]}... -> {ev.sha256[:12]}...")
    return [RuleHit(f"{path}|{ev.data['change']}", f"Monitored file {ev.data['change']}: {path}", ev, [ev], conds, sev)]


# ---- SHIELD-006 ------------------------------------------------------------------------------
def outbound_rate(engine, rule: Rule, ev: Event) -> list[RuleHit]:
    if ev.kind != "network_connection" or not ev.proc_key or ev.data.get("direction") != "outbound" or ev.data.get("remote_ip") is None:
        return []
    p = rule.params
    if ev.data.get("initial"):
        return []                     # already-open connections at start are not "new connections in a window"
    if p.get("public_only", True) and not _is_public(ev):
        return []
    start0 = engine.history.start_of(ev.proc_key)
    if matches_any(ev.image or (start0.image if start0 else None), p.get("ignore_image_patterns", [])):
        return []
    name = (ev.name or basename(ev.image) or "").lower()
    if name in [n.lower() for n in p.get("ignore_processes", [])] or name in [n.lower() for n in engine.config.lists["allowlist_process_names"]]:
        return []
    st = engine.rate_state.setdefault((rule.id, ev.proc_key), {"seen": set(), "win": deque()})
    five = (ev.data.get("local_port"), ev.data["remote_ip"], ev.data.get("remote_port"))
    if five in st["seen"]:
        return []                     # same socket re-observed by a later poll: not a new connection
    st["seen"].add(five)
    if len(st["seen"]) > 5000:
        st["seen"].clear()
    st["win"].append((ev.ts, ev))
    cutoff = ev.ts - timedelta(seconds=p["window_seconds"])
    while st["win"] and st["win"][0][0] < cutoff:
        st["win"].popleft()
    evs = [e for _, e in st["win"]]
    dests = {e.data["remote_ip"] for e in evs}
    over_d = "max_distinct_destinations" in p and len(dests) > p["max_distinct_destinations"]
    over_c = "max_new_connections" in p and len(evs) > p["max_new_connections"]
    if not (over_d or over_c):
        return []
    conds = []
    if over_d:
        conds.append(f"{len(dests)} distinct destinations in {p['window_seconds']}s (threshold {p['max_distinct_destinations']})")
    if over_c:
        conds.append(f"{len(evs)} new connections in {p['window_seconds']}s (threshold {p['max_new_connections']})")
    start = engine.history.start_of(ev.proc_key)
    return [RuleHit(ev.proc_key, f"'{ev.name}' opened {len(evs)} new outbound connections to {len(dests)} distinct destinations within {p['window_seconds']}s",
                    ev, evs[-5:], conds, process_event=start or ev)]


# ---- SHIELD-007 ------------------------------------------------------------------------------
def sysmon_chain(engine, rule: Rule, ev: Event) -> list[RuleHit]:
    if ev.kind != "network_connection" or ev.source != "sysmon" or not ev.proc_key or ev.data.get("direction") != "outbound":
        return []
    start = engine.history.start_of(ev.proc_key)
    if not start or start.source != "sysmon":
        return []
    win = rule.params["window_seconds"]
    if not (timedelta(0) <= ev.ts - start.ts <= timedelta(seconds=win)):
        return []
    parent = engine.history.parent_of(start)
    parent_img = start.parent_image or (parent.image if parent else None)
    for chain in rule.params.get("chains", []):
        conds = []
        if "image_regex" in chain:
            if not (start.image and re.search(chain["image_regex"], start.image)):
                continue
            conds.append(f"image matches /{chain['image_regex']}/")
        if "parent_regex" in chain:
            if not (parent_img and re.search(chain["parent_regex"], parent_img)):
                continue
            conds.append(f"parent image matches /{chain['parent_regex']}/")
        if chain.get("require_suspicious_path"):
            pat = _suspicious(engine, start.image)
            if not pat:
                continue
            conds.append(f"image in suspicious location '{pat}'")
        if chain.get("require_public_connection"):
            if not _is_public(ev):
                continue
            conds.append("connection to a public address")
        if not conds:
            continue
        conds.append(f"same ProcessGuid {ev.proc_key}; connection {int((ev.ts - start.ts).total_seconds())}s after process creation (window {win}s)")
        return [RuleHit(f"{ev.proc_key}|{chain.get('name', 'chain')}", f"Sysmon chain '{chain.get('name', 'chain')}': {basename(parent_img) or '?'} -> {start.name} "
                                                                        f"-> {ev.data.get('remote_ip')}:{ev.data.get('remote_port')}",
                        start, [e for e in [parent, start, ev] if e], conds, process_event=start)]
    return []


# ---- SHIELD-008 ------------------------------------------------------------------------------
def persistence_exec(engine, rule: Rule, ev: Event) -> list[RuleHit]:
    win = timedelta(seconds=rule.params["window_seconds"])
    hits: list[RuleHit] = []
    if ev.kind == "process_start" and ev.image:
        img = norm(ev.image)
        for p in engine.history.persist:
            t = p.data.get("target_path")
            if p.data.get("change") in ("added", "modified") and t and norm(t) == img and timedelta(0) <= ev.ts - p.ts <= win:
                hits.append(_pe_hit(engine, p, ev))
    elif ev.kind == "persistence_change" and ev.data.get("change") in ("added", "modified") and ev.data.get("target_path"):
        t = norm(ev.data["target_path"])
        for s in engine.history.procs.values():
            if s.image and norm(s.image) == t and timedelta(0) <= s.ts - ev.ts <= win:
                hits.append(_pe_hit(engine, ev, s))
    return hits


def _pe_hit(engine, persist_ev: Event, start: Event) -> RuleHit:
    d = persist_ev.data
    sev = "high" if _suspicious(engine, start.image) else None
    conds = [f"startup entry '{d.get('entry_name')}' {d.get('change')} at {d.get('location')}",
             f"process started from the referenced path {int((start.ts - persist_ev.ts).total_seconds())}s later"]
    if sev:
        conds.append("referenced path is in a configured suspicious location")
    return RuleHit(f"{d.get('location')}|{d.get('entry_name')}|{start.proc_key}",
                   f"Startup entry '{d.get('entry_name')}' was {d.get('change')} and '{start.name}' then ran from {start.image}",
                   start, [persist_ev, start], conds, sev, process_event=start)


# ---- SHIELD-009 ------------------------------------------------------------------------------
def ioc_match(engine, rule: Rule, ev: Event) -> list[RuleHit]:
    wl = engine.watchlist
    if wl is None or wl.empty():
        return []
    hits: list[RuleHit] = []

    def add(kind: str, value: str, meta: dict) -> None:
        note = meta.get("note") or ""
        hits.append(RuleHit(f"{kind}:{value}:{ev.proc_key or ev.data.get('path') or ''}",
                            f"Exact watchlist match ({kind}) '{value}': an investigation lead, not proof of compromise",
                            ev, [ev], [f"exact match against local watchlist ({kind})", f"watchlist source: {meta.get('list_source') or 'n/a'}, updated {meta.get('updated') or 'n/a'}"
                                       + (f", note: {note}" if note else "")], process_event=ev if ev.kind in ("process_start", "network_connection") else None))

    if ev.sha256 and ev.sha256.lower() in wl.hashes:
        add("sha256", ev.sha256.lower(), wl.hashes[ev.sha256.lower()])
    rip = ev.data.get("remote_ip")
    if rip and rip in wl.ips:
        add("ip", rip, wl.ips[rip])
    for path in (ev.image, ev.data.get("path"), ev.data.get("target_path")):
        pat = matches_any(path, list(wl.paths)) if path else None
        if pat:
            add("path", norm(path), wl.paths[pat])
            break
    if ev.kind in ("process_start", "network_connection") and ev.image:
        b = basename(ev.image)
        if b in wl.images:
            add("image_name", b, wl.images[b])
    return hits


EVALUATORS: dict[str, Callable] = {
    "exec_location": exec_location, "parent_child": parent_child, "persistence_change": persistence_change,
    "proc_net_correlation": proc_net_correlation, "fim_change": fim_change, "outbound_rate": outbound_rate,
    "sysmon_chain": sysmon_chain, "persistence_exec": persistence_exec, "ioc_match": ioc_match,
}
