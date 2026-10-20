"""Detection engine: ingests normalised events in time order, runs enabled rules, de-duplicates alerts.

Alerts are only produced from telemetry that was actually observed. Severity and confidence come from the rule
configuration plus explicit, listed conditions, never from an opaque score.
"""
from __future__ import annotations

import hashlib
from datetime import timedelta
from typing import Iterable

from spyshield.core.config import Config, Watchlist
from spyshield.core.models import SEV_RANK, Alert, Event, iso
from spyshield.detection.correlation import History
from spyshield.detection.rules import EVALUATORS, RuleHit

POLLING_NOTE = " Observed via polling: short-lived processes/connections between polls can be missed."


class Engine:
    def __init__(self, config: Config, watchlist: Watchlist | None = None, host: str | None = None):
        self.config = config
        self.watchlist = watchlist
        self.host = host
        self.history = History(int(config.settings["max_history_events"]))
        self.cooldown = timedelta(seconds=float(config.settings["cooldown_seconds"]))
        self.rate_state: dict = {}
        self._last: dict[tuple[str, str], Alert] = {}
        self._seq = 0
        self.alerts: list[Alert] = []
        self.stats = {"events": 0, "alerts": 0, "suppressed": 0, "by_rule": {}}

    def _prepare(self, ev: Event) -> None:
        self._seq += 1
        ev.seq = self._seq
        self.stats["events"] += 1

    def ingest(self, ev: Event) -> list[Alert]:
        """Evaluate one event (events must arrive in non-decreasing time order; use process_batch for offline data)."""
        self._prepare(ev)
        self.history.add(ev)
        new: list[Alert] = []
        for rule in self.config.rules:
            if not rule.enabled:
                continue
            for hit in EVALUATORS[rule.type](self, rule, ev):
                a = self._emit(rule, hit, ev)
                if a:
                    new.append(a)
        return new

    def process_batch(self, events: Iterable[Event]) -> list[Alert]:
        """Offline analysis: sort by (timestamp, arrival) so out-of-order exports still correlate correctly."""
        evs = list(events)
        for i, e in enumerate(evs):
            e.seq = i
        evs.sort(key=lambda e: (e.ts, e.seq))
        out: list[Alert] = []
        for e in evs:
            out.extend(self.ingest(e))
        return out

    def _emit(self, rule, hit: RuleHit, trigger: Event) -> Alert | None:
        key = (rule.id, hit.subject)
        prev = self._last.get(key)
        if prev and trigger.ts - prev.ts < self.cooldown:
            prev.suppressed_count += 1
            self.stats["suppressed"] += 1
            return None
        sev = hit.severity or rule.severity
        pe = hit.process_event or hit.anchor
        polling = any(e.source == "psutil" for e in hit.evidence)
        alert = Alert(
            alert_id="A-" + hashlib.sha1(f"{rule.id}|{hit.subject}|{iso(trigger.ts)}".encode()).hexdigest()[:12],
            rule_id=rule.id, title=rule.title, severity=sev, ts=trigger.ts, host=self.host or trigger.host,
            observation=hit.observation, subject=hit.subject,
            process={k: v for k, v in {"pid": pe.pid, "name": pe.name, "image": pe.image, "user": pe.user, "cmdline": pe.cmdline,
                                       "parent_image": pe.parent_image, "proc_key": pe.proc_key, "sha256": pe.sha256}.items() if v},
            evidence=[e.brief() for e in hit.evidence], conditions_met=hit.conditions, confidence=rule.confidence,
            limitations=(rule.limitations + hit.extra_limitations + (POLLING_NOTE if polling else "")).strip(),
            mitre=list(rule.mitre) if hit.mitre is None else hit.mitre,
            false_positives=list(rule.false_positives), investigation_steps=list(rule.action))
        self._last[key] = alert
        self.alerts.append(alert)
        self.stats["alerts"] += 1
        self.stats["by_rule"][rule.id] = self.stats["by_rule"].get(rule.id, 0) + 1
        return alert

    def sorted_alerts(self) -> list[Alert]:
        return sorted(self.alerts, key=lambda a: (-SEV_RANK[a.severity], a.ts, a.rule_id))
