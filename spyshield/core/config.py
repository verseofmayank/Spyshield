"""Loading and validation of config/rules.yaml and the optional IOC watchlist."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from spyshield.core.models import SEVERITIES

RULE_TYPES = {"exec_location", "parent_child", "persistence_change", "proc_net_correlation", "fim_change",
              "outbound_rate", "sysmon_chain", "persistence_exec", "ioc_match"}
TELEMETRY = {"process", "network", "persistence", "fim", "sysmon", "watchlist"}
CONFIDENCE = {"low", "medium", "high"}
_MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

DEFAULT_SETTINGS: dict[str, Any] = {
    "poll_interval_seconds": 2.0,
    "cooldown_seconds": 300,
    "max_history_events": 20000,
    "hash_executables": False,
    "hash_max_megabytes": 50,
    "fim_max_file_megabytes": 50,
    "fim_max_files": 20000,
    "retention_max_events": 200000,
    "retention_days": 30,
}

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[2] / "config" / "rules.yaml"
DEFAULT_IOC_PATH = Path(__file__).resolve().parents[2] / "config" / "ioc.yaml"


class ConfigError(ValueError):
    """Invalid configuration; message lists every problem found."""


@dataclass
class Rule:
    id: str
    title: str
    description: str
    telemetry: list[str]
    type: str
    severity: str
    params: dict[str, Any] = field(default_factory=dict)
    mitre: list[dict[str, str]] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    action: list[str] = field(default_factory=list)
    confidence: str = "low"
    limitations: str = ""
    enabled: bool = True


@dataclass
class Config:
    settings: dict[str, Any]
    lists: dict[str, list[str]]
    rules: list[Rule]
    source: str = ""

    def rule(self, rule_id: str) -> Rule | None:
        return next((r for r in self.rules if r.id == rule_id), None)


@dataclass
class Watchlist:
    hashes: dict[str, dict] = field(default_factory=dict)       # sha256 -> {note}
    ips: dict[str, dict] = field(default_factory=dict)
    paths: dict[str, dict] = field(default_factory=dict)        # normalised glob -> {note}
    images: dict[str, dict] = field(default_factory=dict)       # lowercase basename -> {note}
    source: str = ""
    updated: str = ""

    def empty(self) -> bool:
        return not (self.hashes or self.ips or self.paths or self.images)


def _num(params: dict, key: str, errs: list[str], rid: str, positive=True) -> None:
    v = params.get(key)
    if not isinstance(v, (int, float)) or isinstance(v, bool) or (positive and v <= 0):
        errs.append(f"{rid}: params.{key} must be a positive number (got {v!r})")


def validate_rule_params(rule: Rule, errs: list[str]) -> None:
    p, rid = rule.params, rule.id
    t = rule.type
    if t == "proc_net_correlation":
        _num(p, "window_seconds", errs, rid)
    elif t == "outbound_rate":
        _num(p, "window_seconds", errs, rid)
        if "max_distinct_destinations" not in p and "max_new_connections" not in p:
            errs.append(f"{rid}: outbound_rate needs max_distinct_destinations and/or max_new_connections")
        for k in ("max_distinct_destinations", "max_new_connections"):
            if k in p:
                _num(p, k, errs, rid)
    elif t == "persistence_exec":
        _num(p, "window_seconds", errs, rid)
    elif t == "sysmon_chain":
        _num(p, "window_seconds", errs, rid)
        chains = p.get("chains", [])
        if not isinstance(chains, list):
            errs.append(f"{rid}: params.chains must be a list")
        for i, c in enumerate(chains if isinstance(chains, list) else []):
            for k in ("image_regex", "parent_regex"):
                if k in c:
                    try:
                        re.compile(c[k])
                    except re.error as e:
                        errs.append(f"{rid}: chains[{i}].{k} is not a valid regex ({e})")
    elif t == "parent_child":
        pairs = p.get("pairs")
        if not isinstance(pairs, list) or not pairs:
            errs.append(f"{rid}: params.pairs must be a non-empty list of {{parent: [...], child: [...]}}")
        else:
            for i, pr in enumerate(pairs):
                if not (isinstance(pr, dict) and isinstance(pr.get("parent"), list) and isinstance(pr.get("child"), list)):
                    errs.append(f"{rid}: pairs[{i}] needs 'parent' and 'child' lists")
    elif t == "fim_change":
        for i, ps in enumerate(p.get("path_severity", []) or []):
            if not isinstance(ps, dict) or ps.get("severity") not in SEVERITIES or "prefix" not in ps:
                errs.append(f"{rid}: path_severity[{i}] needs prefix and a valid severity")
        if p.get("default_severity", "medium") not in SEVERITIES:
            errs.append(f"{rid}: default_severity must be one of {SEVERITIES}")


def validate(raw: Any) -> list[str]:
    errs: list[str] = []
    if not isinstance(raw, dict):
        return ["top level of the rules file must be a mapping"]
    rules = raw.get("rules")
    if not isinstance(rules, list) or not rules:
        errs.append("'rules' must be a non-empty list")
        return errs
    seen: set[str] = set()
    for i, r in enumerate(rules):
        rid = r.get("id") if isinstance(r, dict) else None
        label = rid or f"rules[{i}]"
        if not isinstance(r, dict):
            errs.append(f"{label}: must be a mapping")
            continue
        for k in ("id", "title", "description", "type", "severity", "telemetry", "false_positives", "action"):
            if not r.get(k):
                errs.append(f"{label}: missing required field '{k}'")
        if rid in seen:
            errs.append(f"{label}: duplicate rule id")
        seen.add(rid)
        if r.get("severity") and r["severity"] not in SEVERITIES:
            errs.append(f"{label}: severity must be one of {SEVERITIES}")
        if r.get("type") and r["type"] not in RULE_TYPES:
            errs.append(f"{label}: unknown type '{r['type']}' (known: {sorted(RULE_TYPES)})")
        tel = r.get("telemetry") or []
        if not isinstance(tel, list) or any(t not in TELEMETRY for t in tel):
            errs.append(f"{label}: telemetry must be a list from {sorted(TELEMETRY)}")
        if r.get("confidence", "low") not in CONFIDENCE:
            errs.append(f"{label}: confidence must be one of {sorted(CONFIDENCE)}")
        for m in r.get("mitre", []) or []:
            if not isinstance(m, dict) or not _MITRE_RE.match(str(m.get("id", ""))):
                errs.append(f"{label}: invalid MITRE reference {m!r} (expected id like T1547.001)")
        for k in ("false_positives", "action"):
            if r.get(k) and not isinstance(r[k], list):
                errs.append(f"{label}: {k} must be a list of strings")
        if r.get("type") in RULE_TYPES and isinstance(r.get("params", {}), dict):
            validate_rule_params(_to_rule(r), errs)
    lists = raw.get("lists", {}) or {}
    for k, v in lists.items():
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            errs.append(f"lists.{k} must be a list of strings")
    st = raw.get("settings", {}) or {}
    for k, v in st.items():
        if k not in DEFAULT_SETTINGS:
            errs.append(f"settings.{k} is not a known setting")
        elif isinstance(DEFAULT_SETTINGS[k], bool) != isinstance(v, bool) or (not isinstance(v, bool) and not isinstance(v, (int, float))):
            errs.append(f"settings.{k} has the wrong type")
    if "poll_interval_seconds" in st and isinstance(st["poll_interval_seconds"], (int, float)) and st["poll_interval_seconds"] < 0.5:
        errs.append("settings.poll_interval_seconds must be >= 0.5 (bounded polling)")
    return errs


def _to_rule(r: dict) -> Rule:
    return Rule(id=str(r.get("id", "")), title=r.get("title", ""), description=r.get("description", ""),
                telemetry=list(r.get("telemetry") or []), type=r.get("type", ""), severity=r.get("severity", ""),
                params=dict(r.get("params") or {}), mitre=list(r.get("mitre") or []),
                false_positives=list(r.get("false_positives") or []), action=list(r.get("action") or []),
                confidence=r.get("confidence", "low"), limitations=r.get("limitations", ""),
                enabled=bool(r.get("enabled", True)))


def load_config(path: str | Path | None = None) -> Config:
    p = Path(path) if path else DEFAULT_RULES_PATH
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read rules file {p}: {exc.strerror}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"rules file {p} is not valid YAML: {exc}") from exc
    errs = validate(raw)
    if errs:
        raise ConfigError("invalid rules configuration:\n  - " + "\n  - ".join(errs))
    settings = {**DEFAULT_SETTINGS, **(raw.get("settings") or {})}
    lists = {k: list(v) for k, v in (raw.get("lists") or {}).items()}
    for k in ("suspicious_path_patterns", "allowlist_image_patterns", "allowlist_process_names"):
        lists.setdefault(k, [])
    return Config(settings, lists, [_to_rule(r) for r in raw["rules"]], str(p))


def load_watchlist(path: str | Path | None = None) -> Watchlist:
    """Load the local IOC watchlist. A missing default file means an empty watchlist."""
    from spyshield.core.pathutil import norm
    p = Path(path) if path else DEFAULT_IOC_PATH
    if not p.exists():
        if path:
            raise ConfigError(f"watchlist file not found: {p}")
        return Watchlist()
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot load watchlist {p}: {exc}") from exc
    wl = Watchlist(source=str(raw.get("source", "")), updated=str(raw.get("updated", "")), )
    errs = []
    for item in raw.get("indicators", []) or []:
        t, v = str(item.get("type", "")), str(item.get("value", "")).strip()
        meta = {"note": item.get("note", ""), "list_source": wl.source, "updated": wl.updated}
        if t == "sha256":
            if not re.fullmatch(r"[0-9a-fA-F]{64}", v):
                errs.append(f"invalid sha256 indicator {v[:20]!r}")
                continue
            wl.hashes[v.lower()] = meta
        elif t == "ip":
            import ipaddress
            try:
                wl.ips[str(ipaddress.ip_address(v))] = meta
            except ValueError:
                errs.append(f"invalid ip indicator {v!r}")
        elif t == "path":
            wl.paths[norm(v)] = meta
        elif t == "image_name":
            wl.images[v.lower()] = meta
        else:
            errs.append(f"unknown indicator type {t!r}")
    if errs:
        raise ConfigError("invalid watchlist:\n  - " + "\n  - ".join(errs))
    return wl
