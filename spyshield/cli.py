"""SpyShield command-line interface (Click + Rich). Read-only: nothing here modifies the host."""
from __future__ import annotations

import json
import os
import platform
import sys
import time
import traceback
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

import click
from rich.console import Console
from rich.markup import escape as esc
from rich.table import Table

from spyshield import __version__
from spyshield.collectors import filesystem, network, persistence, processes, sysmon
from spyshield.core.config import Config, ConfigError, Watchlist, load_config, load_watchlist
from spyshield.core.models import Alert, Event, utcnow
from spyshield.core.storage import BaselineExists, Storage, StorageError, default_db_path
from spyshield.detection.engine import Engine
from spyshield.reporting import terminal
from spyshield.reporting.export import build_report, write_reports

CTX = dict(help_option_names=["-h", "--help"], max_content_width=100)
console = Console(highlight=False)
err = Console(stderr=True, highlight=False)
HOST = processes.HOST


@dataclass
class App:
    config: Config
    watchlist: Watchlist
    db_path: Path
    verbose: bool

    def storage(self) -> Storage:
        return Storage(self.db_path)

    def engine(self) -> Engine:
        return Engine(self.config, self.watchlist, host=HOST)


def is_elevated() -> bool:
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:  # noqa: BLE001
        return False


class Group(click.Group):
    def invoke(self, ctx):
        try:
            return super().invoke(ctx)
        except (ConfigError, StorageError, filesystem.FimError, ValueError) as exc:
            err.print(f"[bold red]Error:[/] {esc(str(exc))}")
            ctx.exit(2)
        except click.ClickException:
            raise
        except (KeyboardInterrupt, EOFError):
            err.print("[yellow]Interrupted.[/]")
            ctx.exit(130)
        except Exception as exc:  # noqa: BLE001
            if "-v" in sys.argv or "--verbose" in sys.argv:
                err.print(esc(traceback.format_exc()))
            err.print(f"[bold red]Unexpected error:[/] {esc(type(exc).__name__)}: {esc(str(exc))[:200]} [dim](re-run with --verbose)[/]")
            ctx.exit(1)


@click.group(cls=Group, context_settings=CTX)
@click.version_option(__version__, "--version", prog_name="SpyShield")
@click.option("--db", type=click.Path(dir_okay=False), default=None, help="SQLite investigation database (default ./spyshield-data/spyshield.db).")
@click.option("--rules", "rules_path", type=click.Path(dir_okay=False), default=None, help="Rules file (default config/rules.yaml).")
@click.option("--ioc", "ioc_path", type=click.Path(dir_okay=False), default=None, help="Local IOC watchlist (default config/ioc.yaml).")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output and tracebacks.")
@click.pass_context
def cli(ctx, db, rules_path, ioc_path, verbose):
    """
    \b
    SpyShield: host-based intrusion detection & endpoint monitoring.
    Read-only and transparent. It reports observations for an analyst to
    review; it never terminates processes, edits the Registry or sends
    telemetry anywhere. Alerts are leads, not verdicts of malware.

    \b
    Quick start:
      python spyshield.py demo                      (offline, synthetic data)
      python spyshield.py scan
      python spyshield.py baseline --path ./samples/monitored
      python spyshield.py fim --path ./samples/monitored
      python spyshield.py monitor --duration 60
      python spyshield.py analyze --events samples/sysmon_events.xml
      python spyshield.py alerts
      python spyshield.py report --format html
    """
    if "--help" in sys.argv or "-h" in sys.argv:
        return
    ctx.obj = App(load_config(rules_path), load_watchlist(ioc_path), Path(db) if db else default_db_path(), verbose)
    if ctx.invoked_subcommand not in (None, "rules"):
        terminal.banner(console)


def _finish(app: App, command: str, events: list[Event], alerts: list[Alert], notes: str = "") -> None:
    """Persist and print the standard summary."""
    st = app.storage()
    try:
        sid = st.start_scan(command, HOST, notes)
        st.save_events(events, sid)
        st.save_alerts(alerts, sid)
        st.prune(int(app.config.settings["retention_max_events"]), float(app.config.settings["retention_days"]))
    finally:
        st.close()
    terminal.alerts_table(console, alerts, detail=app.verbose)
    terminal.summary_line(console, events, alerts)
    console.print(f"[dim]Saved to {esc(str(app.db_path))}. Review with: spyshield alerts   |   spyshield report --format html[/]")


def _privilege_note() -> None:
    if not is_elevated():
        console.print("[dim]Running without elevated privileges: some process details and connection-to-process links may be unavailable "
                      "(reported, not guessed).[/]")


# ----------------------------------------------------------------------------------------------- scan
@cli.command(context_settings=CTX)
@click.option("--hash", "hash_exe", is_flag=True, help="Compute SHA-256 of process images (size-limited; opt-in).")
@click.pass_obj
def scan(app: App, hash_exe):
    """One read-only endpoint snapshot: processes, connections, persistence (vs. baseline) -> alerts."""
    _privilege_note()
    s = app.config.settings
    tracker = processes.ProcessTracker(hash_executables=hash_exe or s["hash_executables"], hash_max_bytes=int(s["hash_max_megabytes"]) * 1024 * 1024)
    procs = processes.snapshot()
    events = tracker.update(procs)
    net_events, nstats = network.collect(procs, initial=True)  # one snapshot: nothing is 'new in a window'
    events += net_events
    notes = []
    st = app.storage()
    try:
        base = st.load_persistence_baseline(HOST)
    finally:
        st.close()
    sup = persistence.supported()
    if sup["support"] == "unsupported":
        notes.append(f"persistence inspection unsupported on {sup['platform']}")
    snap = persistence.snapshot()
    if base:
        events += persistence.changes_to_events(persistence.diff(base, snap))
    else:
        console.print("[yellow]No persistence baseline stored[/] (run `spyshield persistence --save-baseline` on a trusted host); persistence changes cannot be reported yet.")
    console.print(f"[bold]Collected:[/] {len(procs)} processes ({tracker.stats['access_limited']} with limited access), "
                  f"{nstats['total']} established connections ({nstats['attributed']} attributed to a process"
                  + (", connection table access denied" if nstats["denied"] else "") + f"), {len(snap['entries'])} startup entries "
                  f"[dim]({sup['support']})[/]")
    alerts = app_engine_run(app, events)
    _finish(app, "scan", events, alerts, "; ".join(notes))


def app_engine_run(app: App, events: list[Event]) -> list[Alert]:
    eng = app.engine()
    eng.process_batch(events)
    return eng.sorted_alerts()


# ------------------------------------------------------------------------------------------ processes
@cli.command(context_settings=CTX)
@click.option("--limit", type=click.IntRange(1, 5000), default=40, show_default=True)
@click.option("--sort", "sort_by", type=click.Choice(["start", "pid", "name", "memory"]), default="start", show_default=True)
@click.option("--hash", "hash_exe", is_flag=True, help="Show SHA-256 of images (opt-in; size-limited).")
@click.pass_obj
def processes_cmd(app: App, limit, sort_by, hash_exe):
    """List accessible process information (read-only)."""
    _privilege_note()
    procs = processes.snapshot()
    key = {"start": lambda p: -(p.create_time or 0), "pid": lambda p: p.pid, "name": lambda p: (p.name or "").lower(), "memory": lambda p: -(p.rss or 0)}[sort_by]
    t = Table(title=f"Processes ({len(procs)} total, showing {min(limit, len(procs))})", title_justify="left", header_style="bold", show_edge=False)
    for c in ("PID", "PPID", "Name", "User", "Started (UTC)", "Image", "SHA-256" if hash_exe else "Access"):
        t.add_column(c, overflow="fold")
    limited = 0
    for p in sorted(procs, key=key)[:limit]:
        started = time.strftime("%m-%d %H:%M:%S", time.gmtime(p.create_time)) if p.create_time else "?"
        sha = ""
        if hash_exe and p.exe:
            h, why = processes.sha256_file(p.exe, int(app.config.settings["hash_max_megabytes"]) * 1024 * 1024)
            sha = (h[:16] + "...") if h else f"({why})"
        t.add_row(str(p.pid), str(p.ppid), esc(p.name or "?"), esc(p.username or "?"), started, esc(p.exe or "n/a"),
                  sha if hash_exe else ("limited" if p.access_limited else "ok"))
    limited = sum(p.access_limited for p in procs)
    console.print(t)
    console.print(f"[dim]{limited} processes had inaccessible fields (shown as n/a). Names are context only; SpyShield does not judge processes by name.[/]")


cli.add_command(processes_cmd, "processes")


# --------------------------------------------------------------------------------------------- network
@cli.command("network", context_settings=CTX)
@click.option("--all-states", is_flag=True, help="Include LISTEN/TIME_WAIT etc. (default: outbound ESTABLISHED/SYN_SENT).")
@click.option("--limit", type=click.IntRange(1, 5000), default=60, show_default=True)
@click.pass_obj
def network_cmd(app: App, all_states, limit):
    """Show process-associated network connections with address classification."""
    _privilege_note()
    procs = processes.snapshot()
    events, stats = network.collect(procs, states=None if not all_states else {"ESTABLISHED", "SYN_SENT", "LISTEN", "TIME_WAIT", "CLOSE_WAIT", "FIN_WAIT1", "FIN_WAIT2"})
    t = Table(title=f"Connections ({stats['total']}; {stats['attributed']} attributed to a process)", title_justify="left", header_style="bold", show_edge=False)
    for c in ("PID", "Process", "Local", "Remote", "Class", "State", "Proto"):
        t.add_column(c, overflow="fold")
    for e in sorted(events, key=lambda e: (e.data["remote_class"] != "public", e.name or ""))[:limit]:
        d = e.data
        t.add_row(str(e.pid or "?"), esc(e.name or "(unattributed)"), f"{d['local_ip']}:{d['local_port']}", f"{d['remote_ip']}:{d['remote_port']}",
                  d["remote_class"], d["state"], d["protocol"])
    console.print(t)
    if stats["denied"]:
        console.print("[yellow]Access to the connection table was denied; run from an elevated shell for fuller results.[/]")
    console.print("[dim]Unusual ports are NOT treated as malicious. A polled snapshot cannot show short-lived connections.[/]")


# ----------------------------------------------------------------------------------------- persistence
@cli.command("persistence", context_settings=CTX)
@click.option("--save-baseline", is_flag=True, help="Store the current startup entries as the trusted baseline.")
@click.option("--diff", "do_diff", is_flag=True, help="Compare with the stored baseline and raise alerts for changes.")
@click.pass_obj
def persistence_cmd(app: App, save_baseline, do_diff):
    """Inspect startup persistence (Run/RunOnce, Startup folders). Strictly read-only."""
    sup = persistence.supported()
    console.print(f"[bold]Platform support:[/] {sup['platform']}: {sup['support']}")
    snap = persistence.snapshot()
    t = Table(title=f"Startup entries ({len(snap['entries'])})", title_justify="left", header_style="bold", show_edge=False)
    for c in ("Location", "Name", "Target / command"):
        t.add_column(c, overflow="fold")
    for e in snap["entries"].values():
        t.add_row(esc(e["location"]), esc(e["name"]), esc(e["command"] or ""))
    console.print(t)
    if snap.get("unreadable"):
        console.print(f"[yellow]Not readable (permissions/absent):[/] {esc(', '.join(snap['unreadable']))}")
    st = app.storage()
    try:
        if save_baseline:
            st.save_persistence(snap, host=HOST, platform=snap["platform"], baseline=True)
            console.print("[green]Baseline stored.[/] Take baselines only on a state you trust.")
        if do_diff:
            base = st.load_persistence_baseline(HOST)
            if not base:
                raise ValueError("no persistence baseline stored; run with --save-baseline first")
            d = persistence.diff(base, snap)
            console.print(f"Changes since baseline: added={len(d['added'])} removed={len(d['removed'])} modified={len(d['modified'])}")
            events = persistence.changes_to_events(d)
            alerts = app_engine_run(app, events)
            _finish(app, "persistence", events, alerts)
    finally:
        st.close()


# ----------------------------------------------------------------------------------------------- FIM
@cli.command(context_settings=CTX)
@click.option("--path", "path", required=True, help="Directory to baseline (explicit; never the whole disk).")
@click.option("--exclude", multiple=True, help="Glob to skip (repeatable), e.g. '*.log'.")
@click.option("--force", is_flag=True, help="Replace an existing baseline deliberately.")
@click.pass_obj
def baseline(app: App, path, exclude, force):
    """Create a file-integrity baseline (SHA-256 + metadata) for a directory. Contents are never stored."""
    root = filesystem.resolve_root(path)
    s = app.config.settings
    files, stats = filesystem.scan_directory(root, exclude=list(exclude), max_file_bytes=int(s["fim_max_file_megabytes"]) * 1024 * 1024,
                                              max_files=int(s["fim_max_files"]))
    st = app.storage()
    try:
        try:
            st.save_baseline(root, list(files.values()), host=HOST, skipped=stats["unreadable"], options={"exclude": list(exclude)}, overwrite=force)
        except BaselineExists as exc:
            raise ValueError(str(exc)) from exc
    finally:
        st.close()
    console.print(f"[green]Baseline created[/] for {esc(root)}: {len(files)} files, {stats['excluded']} excluded, {stats['unreadable']} unreadable, "
                  f"{stats['symlinks']} symlinks (not followed), {stats['hash_skipped']} hash-skipped"
                  + (" [yellow](file limit reached: baseline truncated)[/]" if stats["truncated"] else ""))


@cli.command(context_settings=CTX)
@click.option("--path", "path", required=True, help="Directory to compare against its stored baseline.")
@click.option("--watch", "watch_seconds", type=click.FloatRange(1, 3600), default=None, help="Instead of a one-off compare, watch in real time for N seconds.")
@click.pass_obj
def fim(app: App, path, watch_seconds):
    """Compare current files with the stored baseline (or --watch for real-time changes)."""
    root = filesystem.resolve_root(path)
    st = app.storage()
    try:
        loaded = st.load_baseline(root)
    finally:
        st.close()
    if not loaded:
        raise ValueError(f"no baseline for {root}; create one with: spyshield baseline --path {path}")
    base_files, meta = loaded
    exclude = json.loads(meta["options"]).get("exclude", [])
    s = app.config.settings
    events: list[Event] = []
    if watch_seconds:
        console.print(f"Watching {esc(root)} for {watch_seconds:.0f}s (Ctrl+C to stop)...")
        try:
            counts = filesystem.watch(root, events.append, duration=watch_seconds, exclude=exclude, host=HOST,
                                      max_file_bytes=int(s["fim_max_file_megabytes"]) * 1024 * 1024)
        except KeyboardInterrupt:
            counts = {}
            console.print("[yellow]Interrupted; saving what was observed.[/]")
        console.print(f"Observed: {counts}")
    else:
        cur, stats = filesystem.scan_directory(root, exclude=exclude, max_file_bytes=int(s["fim_max_file_megabytes"]) * 1024 * 1024, max_files=int(s["fim_max_files"]))
        diff = filesystem.compare(base_files, cur)
        events = filesystem.changes_to_events(root, diff, host=HOST)
        console.print(f"Baseline from {esc(meta['created'])}: {len(base_files)} files. Now: {len(cur)} files "
                      f"([bold]{len(diff['created'])} created, {len(diff['modified'])} modified, {len(diff['deleted'])} deleted[/]; {stats['unreadable']} unreadable)")
        for k, items in diff.items():
            for r in items[:20]:
                console.print(f"  {k:<9} {esc(r['relpath'])}")
    alerts = app_engine_run(app, events)
    _finish(app, "fim", events, alerts, root)


# ---------------------------------------------------------------------------------------------- monitor
@cli.command(context_settings=CTX)
@click.option("--duration", type=click.FloatRange(1, 86400), default=60, show_default=True, help="Seconds to monitor (bounded).")
@click.option("--interval", type=click.FloatRange(0.5, 60), default=None, help="Polling interval seconds (default from rules.yaml).")
@click.option("--watch-path", "watch_paths", multiple=True, help="Also watch a baselined directory in real time (repeatable).")
@click.option("--hash", "hash_exe", is_flag=True, help="Hash new process images (opt-in).")
@click.pass_obj
def monitor(app: App, duration, interval, watch_paths, hash_exe):
    """Bounded live monitoring: poll processes and connections, evaluate rules, print alerts as they occur."""
    _privilege_note()
    s = app.config.settings
    interval = interval or float(s["poll_interval_seconds"])
    tracker = processes.ProcessTracker(hash_executables=hash_exe or s["hash_executables"], hash_max_bytes=int(s["hash_max_megabytes"]) * 1024 * 1024)
    eng = app.engine()
    all_events: list[Event] = []
    fim_events: list[Event] = []
    import threading
    stop = threading.Event()
    threads = []
    for wp in watch_paths:
        root = filesystem.resolve_root(wp)
        th = threading.Thread(target=filesystem.watch, args=(root, fim_events.append),
                              kwargs={"duration": duration, "host": HOST, "stop": stop.is_set}, daemon=True)
        th.start()
        threads.append(th)
    console.print(f"Monitoring for {duration:.0f}s every {interval}s. Polling can miss processes/connections that live less than one interval. Ctrl+C to stop.")
    end = time.monotonic() + duration
    shown = 0
    ticks = 0
    try:
        while time.monotonic() < end:
            t0 = time.monotonic()
            procs = processes.snapshot()
            evs = tracker.update(procs)
            nev, _ = network.collect(procs, initial=(ticks == 0))
            batch = evs + nev
            while fim_events:
                batch.append(fim_events.pop(0))
            all_events += batch
            for a in (eng.process_batch(batch)):
                terminal.alerts_table(console, [a], detail=False)
                shown += 1
            ticks += 1
            time.sleep(max(0.0, interval - (time.monotonic() - t0)))
    except KeyboardInterrupt:
        console.print("[yellow]Interrupted by user; saving results.[/]")
    finally:
        stop.set()
        for th in threads:
            th.join(timeout=3)
    console.print(f"\n{ticks} polls; {sum(e.kind == 'process_start' and not e.data.get('initial') for e in all_events)} new processes observed after the initial snapshot.")
    _finish(app, "monitor", all_events, eng.sorted_alerts(), f"duration={duration}s interval={interval}s")


# ---------------------------------------------------------------------------------------------- analyze
@cli.command(context_settings=CTX)
@click.option("--events", "events_path", type=click.Path(exists=True, dir_okay=False), help="Exported Sysmon XML file to analyze offline.")
@click.option("--live-sysmon", is_flag=True, help="Read recent events from the local Sysmon log (needs Sysmon + permissions; UNVERIFIED here).")
@click.option("--count", type=click.IntRange(1, 50000), default=500, show_default=True, help="Events to read with --live-sysmon.")
@click.pass_obj
def analyze(app: App, events_path, live_sysmon, count):
    """Analyze Sysmon events (exported XML) with the same rules, correlating by ProcessGuid."""
    if not events_path and not live_sysmon:
        raise ValueError("give --events <file.xml> (offline) or --live-sysmon")
    if live_sysmon:
        try:
            events, rep = sysmon.read_live(count)
        except RuntimeError as exc:
            raise ValueError(str(exc)) from exc
    else:
        events, rep = sysmon.parse_file(events_path, HOST)
    console.print(f"[bold]Sysmon parse:[/] {rep.parsed} normalized, {rep.malformed} malformed, {rep.skipped_unsupported} unsupported of {rep.total}; "
                  f"event IDs seen: {dict(sorted(rep.by_event_id.items()))}")
    for p in rep.problems[:10]:
        console.print(f"  [yellow]skipped:[/] {esc(p)}")
    if not events:
        console.print("[yellow]No supported events found; nothing to analyze.[/]")
    alerts = app_engine_run(app, events)
    _finish(app, "analyze", events, alerts, events_path or "live-sysmon")


# ----------------------------------------------------------------------------------------------- alerts
@cli.command(context_settings=CTX)
@click.option("--severity", type=click.Choice(["info", "low", "medium", "high"]))
@click.option("--rule", "rule_id")
@click.option("--limit", type=click.IntRange(1, 10000), default=100, show_default=True)
@click.option("--detail", "-d", is_flag=True, help="Show full evidence, conditions and investigation steps.")
@click.pass_obj
def alerts(app: App, severity, rule_id, limit, detail):
    """Show saved alerts from the investigation database."""
    st = app.storage()
    try:
        al = st.load_alerts(severity=severity, rule_id=rule_id, limit=limit)
    finally:
        st.close()
    terminal.alerts_table(console, al, detail=detail)


# ----------------------------------------------------------------------------------------------- report
@cli.command(context_settings=CTX)
@click.option("--format", "formats", multiple=True, type=click.Choice(["json", "csv", "html", "all"]), default=("html",), show_default=True)
@click.option("--out-dir", default="spyshield-reports", show_default=True)
@click.option("--show-hostname", is_flag=True, help="Include the real hostname (default: anonymised id).")
@click.pass_obj
def report(app: App, formats, out_dir, show_hostname):
    """Generate JSON / CSV (alerts) / standalone HTML report from the saved investigation data."""
    st = app.storage()
    try:
        events = st.load_events()
        al = st.load_alerts(limit=10000)
    finally:
        st.close()
    if not events and not al:
        raise ValueError("the database has no events or alerts yet; run scan, fim, monitor or analyze first")
    rep = build_report(al, events, title="SpyShield endpoint investigation", show_hostname=show_hostname)
    paths = write_reports(rep, list(formats), out_dir)
    console.print("[bold green]Report files:[/]")
    for p in paths:
        console.print(f"  {esc(str(p.resolve()))}")


# ------------------------------------------------------------------------------------------------ demo
@cli.command(context_settings=CTX)
@click.option("--out-dir", default="examples/demo-output", show_default=True)
@click.option("--no-report", is_flag=True)
@click.pass_obj
def demo(app: App, out_dir, no_report):
    """Offline demonstration with SYNTHETIC labelled scenarios (no malware, no live system changes)."""
    from spyshield import demo as demomod
    console.print("[bold black on yellow] SYNTHETIC DATA [/] Hand-written scenarios; nothing here ran on or changed your system.\n")
    results = demomod.run_all(app.config, app.watchlist)
    t = Table(title="Scenario results", title_justify="left", header_style="bold", show_edge=False)
    for c in ("ID", "Scenario", "Label", "Rules fired", "Outcome"):
        t.add_column(c, overflow="fold")
    for r in results:
        style = "green" if r.outcome in ("TP", "TN") else "bold red"
        t.add_row(r.id, esc(r.title), r.label, esc(", ".join(r.got) or "(none)"), f"[{style}]{r.outcome}[/]")
    console.print(t)
    m = demomod.metrics(results)
    console.print(f"TP={m['TP']} FN={m['FN']} TN={m['TN']} FP={m['FP']}  precision={m['precision']} recall={m['recall']}")
    console.print(f"[dim]{m['caveat']}[/]\n")
    all_alerts = [a for r in results for a in r.alerts]
    all_events = [e for r in results for e in r.events]
    terminal.alerts_table(console, all_alerts, detail=False)
    demo_db = Path("spyshield-data") / "demo.db"
    st = Storage(demo_db)
    try:
        sid = st.start_scan("demo", "DEMO-HOST", "synthetic")
        st.save_events(all_events, sid)
        st.save_alerts(all_alerts, sid)
    finally:
        st.close()
    console.print(f"[dim]Synthetic events/alerts stored in {esc(str(demo_db))} (separate from your real database).[/]")
    if not no_report:
        evaluation = {**m, "rows": [{"id": r.id, "title": r.title, "label": r.label, "expected": r.expected, "got": r.got, "outcome": r.outcome} for r in results]}
        rep = build_report(all_alerts, all_events, title="SpyShield demo investigation (SYNTHETIC DATA)", mode="synthetic-fixtures",
                           scenario_results=evaluation, notes=["All events are synthetic fixtures; see samples/demo_scenarios.json."])
        paths = write_reports(rep, ["all"], out_dir, stem="spyshield-demo")
        console.print("[bold green]Report files:[/]")
        for p in paths:
            console.print(f"  {esc(str(p.resolve()))}")


# --------------------------------------------------------------------------------------------- rules
@cli.command(context_settings=CTX)
@click.pass_obj
def rules(app: App):
    """List the loaded detection rules (the file was validated on load)."""
    t = Table(title=f"Rules from {app.config.source}", title_justify="left", header_style="bold", show_edge=False)
    for c in ("ID", "Severity", "Type", "Telemetry", "Title"):
        t.add_column(c, overflow="fold")
    for r in app.config.rules:
        t.add_row(r.id, r.severity + ("" if r.enabled else " (disabled)"), r.type, ",".join(r.telemetry), esc(r.title))
    console.print(t)
    wl = app.watchlist
    console.print(f"IOC watchlist: {len(wl.hashes)} hashes, {len(wl.ips)} IPs, {len(wl.paths)} paths, {len(wl.images)} image names "
                  f"(source: {esc(wl.source or 'none')}, updated {esc(wl.updated or 'n/a')})")


# ------------------------------------------------------------------------------------------------ data
@cli.group(context_settings=CTX)
def data():
    """Export, prune or clear stored investigation data."""


@data.command("export", context_settings=CTX)
@click.option("--output", "-o", required=True, type=click.Path(dir_okay=False))
@click.pass_obj
def data_export(app: App, output):
    """Export everything in the database as JSON."""
    st = app.storage()
    try:
        doc = st.export()
    finally:
        st.close()
    Path(output).write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    console.print(f"Exported {doc['counts']} to {esc(str(Path(output).resolve()))}")


@data.command("clear", context_settings=CTX)
@click.option("--yes", is_flag=True, help="Confirm deletion (required).")
@click.option("--include-baselines", is_flag=True, help="Also delete FIM and persistence baselines.")
@click.pass_obj
def data_clear(app: App, yes, include_baselines):
    """Delete stored events/alerts/scans (baselines kept unless --include-baselines)."""
    if not yes:
        raise ValueError("refusing to delete without --yes")
    st = app.storage()
    try:
        removed = st.clear(include_baselines=include_baselines)
    finally:
        st.close()
    console.print(f"Deleted rows: {removed}")


@data.command("prune", context_settings=CTX)
@click.pass_obj
def data_prune(app: App):
    """Apply the retention limits from rules.yaml."""
    st = app.storage()
    try:
        r = st.prune(int(app.config.settings["retention_max_events"]), float(app.config.settings["retention_days"]))
    finally:
        st.close()
    console.print(f"Pruned: {r}")


def main() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    cli(prog_name="spyshield")
