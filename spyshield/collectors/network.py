"""Process-aware network connection collector (psutil).

Polling the connection table can miss short-lived connections and, without elevated rights, cannot attribute
every socket to a PID. No packet capture or payload inspection is done here.
"""
from __future__ import annotations

import ipaddress
import socket
from datetime import datetime
from typing import Any, Callable

import psutil

from spyshield.core.models import Event, utcnow
from spyshield.collectors.processes import HOST, ProcInfo

PROTO = {socket.SOCK_STREAM: "tcp", socket.SOCK_DGRAM: "udp"}


def classify_ip(ip: str | None) -> str:
    """loopback | private | public | reserved | unspecified | invalid"""
    if not ip:
        return "invalid"
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return "invalid"
    if a.version == 6 and getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    if a.is_unspecified:
        return "unspecified"
    if a.is_loopback:
        return "loopback"
    if a.is_multicast or a.is_reserved or a.is_link_local:
        return "reserved"
    if a.is_private:
        return "private"
    if a.version == 4 and a in ipaddress.ip_network("100.64.0.0/10"):
        return "private"
    return "public" if a.is_global else "reserved"


def collect(procs: list[ProcInfo], *, now: datetime | None = None, host: str = HOST,
            connections: Callable[[], list] | None = None, states: set[str] | None = None,
            initial: bool = False) -> tuple[list[Event], dict[str, Any]]:
    """Return (network_connection events, stats). Only ESTABLISHED/SYN_SENT TCP by default (outbound activity).

    initial=True marks connections that already existed when monitoring began; they are context, not "new" activity.
    """
    now = now or utcnow()
    states = states or {"ESTABLISHED", "SYN_SENT"}
    by_pid = {p.pid: p for p in procs}
    stats = {"total": 0, "attributed": 0, "unattributed": 0, "denied": False}
    try:
        conns = connections() if connections else psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError, OSError):
        stats["denied"] = True
        return [], stats
    events: list[Event] = []
    for c in conns:
        if not c.raddr or c.status not in states:
            continue
        stats["total"] += 1
        proc = by_pid.get(c.pid) if c.pid else None
        if proc:
            stats["attributed"] += 1
        else:
            stats["unattributed"] += 1
        rip, rport = c.raddr.ip, c.raddr.port
        events.append(Event(now, "psutil", "network_connection", host, proc.key if proc else None, c.pid, proc.ppid if proc else None,
                            None, proc.exe if proc else None, proc.name if proc else None, None, None, None, None, {
                                "local_ip": c.laddr.ip if c.laddr else None, "local_port": c.laddr.port if c.laddr else None,
                                "remote_ip": rip, "remote_port": rport, "protocol": PROTO.get(c.type, "other"),
                                "state": c.status, "remote_class": classify_ip(rip), "direction": "outbound", "initial": initial}))
    return events, stats
