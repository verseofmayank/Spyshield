"""Rich terminal rendering. Every untrusted string is escaped to prevent markup injection."""
from __future__ import annotations

from rich.console import Console
from rich.markup import escape as esc
from rich.panel import Panel
from rich.table import Table

from spyshield.core.models import SEV_RANK, Alert, Event

BANNER = r"""
 ____              ____  _     _      _     _
/ ___| _ __  _   _/ ___|| |__ (_) ___| | __| |
\___ \| '_ \| | | \___ \| '_ \| |/ _ \ |/ _` |
 ___) | |_) | |_| |___) | | | | |  __/ | (_| |
|____/| .__/ \__, |____/|_| |_|_|\___|_|\__,_|
      |_|    |___/"""

SEV_STYLE = {"high": "bold red", "medium": "dark_orange", "low": "yellow", "info": "cyan"}


def banner(console: Console) -> None:
    console.print(BANNER, style="bold cyan", highlight=False)
    console.print("  [bold white]Host-based intrusion detection & endpoint monitoring[/]   [dim]by Mayank Kumar Karn[/]")
    console.print("  [dim]Defensive and read-only: SpyShield never kills processes or changes your system.[/]\n")


def _t(title: str, *cols: str) -> Table:
    t = Table(title=title, title_justify="left", header_style="bold", show_edge=False, pad_edge=False)
    for c in cols:
        t.add_column(c, overflow="fold")
    return t


def alerts_table(console: Console, alerts: list[Alert], *, detail: bool = False) -> None:
    if not alerts:
        console.print("[green]No alerts.[/] [dim]No rule conditions were met by the telemetry available.[/]")
        return
    t = _t(f"Alerts ({len(alerts)}), observations that need analyst review", "Sev", "Rule", "Time (UTC)", "Observation")
    for a in sorted(alerts, key=lambda x: (-SEV_RANK[x.severity], x.ts)):
        t.add_row(f"[{SEV_STYLE[a.severity]}]{a.severity.upper()}[/]", a.rule_id, a.ts.strftime("%Y-%m-%d %H:%M:%S"),
                  esc(a.observation) + (f" [dim](+{a.suppressed_count} repeats)[/]" if a.suppressed_count else ""))
    console.print(t)
    if detail:
        for a in sorted(alerts, key=lambda x: (-SEV_RANK[x.severity], x.ts)):
            lines = [f"[bold]{esc(a.title)}[/]", f"Observation: {esc(a.observation)}"]
            if a.process:
                lines.append("Process: " + esc(f"{a.process.get('name')} PID {a.process.get('pid')} {a.process.get('image') or ''}"))
            lines += ["Conditions met:"] + [f"  - {esc(c)}" for c in a.conditions_met]
            lines.append(f"Confidence: {a.confidence}. {esc(a.limitations)}")
            if a.mitre:
                lines.append("MITRE: " + esc(", ".join(f"{m['id']} {m.get('name', '')}" for m in a.mitre)))
            lines += ["Investigate:"] + [f"  - {esc(s)}" for s in a.investigation_steps[:3]]
            lines.append(f"Status: {a.status}")
            console.print(Panel("\n".join(lines), title=f"[{SEV_STYLE[a.severity]}]{a.severity.upper()}[/] {a.rule_id} {a.alert_id}", border_style="dim"))


def summary_line(console: Console, events: list[Event], alerts: list[Alert]) -> None:
    sev = {s: sum(a.severity == s for a in alerts) for s in ("high", "medium", "low", "info")}
    console.print(f"\n[bold]Events analyzed:[/] {len(events)}   [bold]Alerts:[/] " +
                  "  ".join(f"[{SEV_STYLE[s]}]{n} {s}[/]" for s, n in sev.items()))
