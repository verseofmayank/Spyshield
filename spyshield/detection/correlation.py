"""Bounded event history and correlation helpers (process lineage, process<->network, persistence<->execution)."""
from __future__ import annotations

from collections import OrderedDict, deque
from datetime import datetime, timedelta

from spyshield.core.models import Event


class History:
    """Keeps recent events indexed for correlation. Memory is bounded by `max_events`."""

    def __init__(self, max_events: int = 20000, max_net_per_proc: int = 500):
        self.max_events = max_events
        self.procs: "OrderedDict[str, Event]" = OrderedDict()      # proc_key -> process_start
        self.pid_index: dict[int, list[str]] = {}                  # pid -> [proc_key...] oldest first
        self.net: dict[str, deque[Event]] = {}
        self.persist: deque[Event] = deque(maxlen=max(1000, max_events // 10))
        self.ended: dict[str, datetime] = {}
        self.max_net_per_proc = max_net_per_proc
        self.dropped = 0

    def add(self, ev: Event) -> None:
        if ev.kind == "process_start" and ev.proc_key:
            if ev.proc_key not in self.procs:
                self.procs[ev.proc_key] = ev
                if ev.pid is not None:
                    self.pid_index.setdefault(ev.pid, []).append(ev.proc_key)
            while len(self.procs) > self.max_events:
                k, old = self.procs.popitem(last=False)
                self.dropped += 1
                if old.pid in self.pid_index:
                    self.pid_index[old.pid] = [x for x in self.pid_index[old.pid] if x != k]
                self.net.pop(k, None)
        elif ev.kind == "network_connection" and ev.proc_key:
            dq = self.net.setdefault(ev.proc_key, deque(maxlen=self.max_net_per_proc))
            dq.append(ev)
        elif ev.kind == "persistence_change":
            self.persist.append(ev)
        elif ev.kind == "process_end" and ev.proc_key:
            self.ended[ev.proc_key] = ev.ts
            if len(self.ended) > self.max_events:
                self.ended.pop(next(iter(self.ended)))

    def start_of(self, proc_key: str | None) -> Event | None:
        return self.procs.get(proc_key) if proc_key else None

    def parent_of(self, ev: Event) -> Event | None:
        """Parent process_start event. Prefers the explicit parent key (Sysmon GUID / pid:ctime);
        falls back to PPID, choosing the newest process with that PID that existed before the child
        (guards against PID reuse)."""
        if ev.parent_key and ev.parent_key in self.procs:
            return self.procs[ev.parent_key]
        if ev.ppid is None:
            return None
        best = None
        for k in self.pid_index.get(ev.ppid, []):
            cand = self.procs.get(k)
            if cand and cand.ts <= ev.ts and (best is None or cand.ts > best.ts):
                best = cand
        return best

    def lineage(self, ev: Event, depth: int = 8) -> list[Event]:
        out, cur, seen = [], ev, {ev.proc_key}
        for _ in range(depth):
            p = self.parent_of(cur)
            if not p or p.proc_key in seen:
                break
            out.append(p)
            seen.add(p.proc_key)
            cur = p
        return out

    def connections(self, proc_key: str | None, since: datetime | None = None, until: datetime | None = None) -> list[Event]:
        evs = list(self.net.get(proc_key or "", []))
        return [e for e in evs if (since is None or e.ts >= since) and (until is None or e.ts <= until)]

    def starts_with_image(self, image_norm: str, after: datetime, before: datetime, norm_fn) -> list[Event]:
        return [e for e in self.procs.values() if e.image and after <= e.ts <= before and norm_fn(e.image) == image_norm]


def within(a: datetime, b: datetime, seconds: float) -> bool:
    """True if b is not before a and at most `seconds` after it."""
    return timedelta(0) <= (b - a) <= timedelta(seconds=seconds)
