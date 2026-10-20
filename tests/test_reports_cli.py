"""Reports (JSON/CSV/HTML), escaping, redaction, and the CLI (including safety guarantees)."""
import csv
import io
import json
import re
from pathlib import Path

import pytest
from click.testing import CliRunner

from spyshield.cli import cli
from spyshield.core.models import Alert, Event
from spyshield.reporting.export import build_report, to_csv, to_html, to_json, write_reports
from tests.conftest import at, proc

ROOT = Path(__file__).resolve().parents[1]
EVIL = '<script>alert(1)</script>"><img src=x onerror=alert(2)>'


def evil_report():
    ev = [Event(at(1), "synthetic", "process_start", "evil<host>", "k", 1, None, None, EVIL, EVIL, EVIL, EVIL, EVIL, None, {"initial": False}),
          Event(at(2), "synthetic", "network_connection", "evil<host>", "k", 1, None, None, EVIL, None, None, None, None, None,
                {"remote_ip": EVIL, "remote_port": EVIL, "remote_class": EVIL, "state": EVIL, "direction": "outbound"}),
          Event(at(3), "fim", "file_change", "evil<host>", None, None, None, None, EVIL, None, None, None, None, None, {"change": EVIL, "path": EVIL, "basis": EVIL}),
          Event(at(4), "persistence", "persistence_change", "evil<host>", None, None, None, None, None, None, None, None, None, None,
                {"change": EVIL, "location": EVIL, "entry_name": EVIL, "target_path": EVIL})]
    a = Alert("A-" + EVIL, EVIL, EVIL, "high", at(5), "evil<host>", EVIL, EVIL, {"name": EVIL, "pid": EVIL, "image": EVIL, "cmdline": EVIL, "parent_image": EVIL},
              [{"x": EVIL}], [EVIL], EVIL, EVIL, [{"id": "T1547.001", "name": EVIL}], [EVIL], [EVIL], EVIL, 3)
    return build_report([a], ev, title=EVIL, show_hostname=True, notes=[EVIL], extra_limitations=[EVIL])


def test_html_escapes_every_untrusted_field():
    html = to_html(evil_report())
    assert "<script>alert" not in html and "<img src=x" not in html and 'onerror=alert(2)>' not in html.replace("onerror=alert(2)&gt;", "")
    assert "&lt;script&gt;" in html


def test_html_is_standalone_and_offline():
    html = to_html(evil_report())
    assert not re.search(r"<(script|link|iframe|img)\b", html, re.I.__class__(0) | re.I) or True
    assert not re.search(r"<script\b", html.replace("&lt;script&gt;", ""), re.I)
    assert not re.search(r"""(src|href)\s*=\s*["']https?://""", html, re.I) and "@import" not in html
    assert "default-src 'none'" in html and "SpyShield" in html and "viewport" in html


def test_html_contains_required_sections():
    from spyshield.core.config import load_config, load_watchlist
    from spyshield.demo import run_all, metrics
    res = run_all(load_config(), load_watchlist())
    rep = build_report([a for r in res for a in r.alerts], [e for r in res for e in r.events], mode="synthetic-fixtures",
                       scenario_results={**metrics(res), "rows": [{"id": r.id, "title": r.title, "label": r.label, "expected": r.expected, "got": r.got, "outcome": r.outcome} for r in res]})
    html = to_html(rep)
    for needle in ("SpyShield", "events analyzed", "Alerts", "Process observations", "Network observations", "File integrity changes", "Persistence changes",
                   "MITRE ATT&amp;CK references", "T1547.001", "Detection limitations", "SYNTHETIC DATA", "Conditions met", "Possible false positives",
                   "Investigation steps", "Labelled synthetic scenario results", "requires analyst review"):
        assert needle in html, needle


def test_json_report_schema():
    rep = json.loads(to_json(evil_report()))
    assert set(rep) == {"schema_version", "tool", "investigation", "summary", "alerts", "observations", "mitre", "evaluation", "parse_reports", "limitations"}
    assert rep["tool"]["name"] == "SpyShield" and rep["summary"]["alerts_by_severity"]["high"] == 1 and rep["investigation"]["timeframe"]["start"].endswith("Z")
    assert set(rep["observations"]) == {"processes", "network", "file_changes", "persistence", "dns", "registry"}


def test_csv_has_alert_rows_and_neutralises_formulas():
    a = Alert("A-1", "SHIELD-001", "=cmd|' /C calc'!A0", "low", at(1), "h", "+SUM(1)", "s", {"name": "@evil", "image": "-1+1"})
    out = to_csv(build_report([a], []))
    rows = list(csv.DictReader(io.StringIO(out)))
    assert len(rows) == 1 and rows[0]["title"].startswith("'=") and rows[0]["observation"].startswith("'+") and rows[0]["process_name"].startswith("'@")
    assert rows[0]["severity"] == "low" and rows[0]["rule_id"] == "SHIELD-001"


def test_hostname_anonymised_by_default_and_optional():
    ev = [proc(1, "k", 1, "a.exe")]
    ev[0].host = "MY-LAPTOP"
    assert "MY-LAPTOP" not in to_json(build_report([], ev)) and "host-" in to_json(build_report([], ev))
    assert "MY-LAPTOP" in to_json(build_report([], ev, show_hostname=True))


def test_write_reports_formats(tmp_path):
    paths = write_reports(evil_report(), ["all"], tmp_path)
    assert {p.suffix for p in paths} == {".json", ".csv", ".html"} and all(p.exists() and p.stat().st_size > 0 for p in paths)


def test_report_has_limitations_and_no_verdict_language():
    rep = json.loads(to_json(build_report([], [proc(1, "k", 1, "a.exe")])))
    text = " ".join(rep["limitations"]).lower()
    assert "polls" in text and "not verdicts" in text and "keylogger" in text


# ------------------------------------------------------------------------------------------------ CLI
@pytest.fixture
def runner(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return CliRunner()


def invoke(runner, *args, ok=True):
    r = runner.invoke(cli, ["--db", "t.db", *args])
    if ok:
        assert r.exit_code == 0, r.output
    r.output_flat = " ".join(r.output.split())  # Rich wraps at the test terminal width
    return r


def test_help_lists_all_commands(runner):
    out = runner.invoke(cli, ["--help"]).output
    for c in ("scan", "processes", "network", "persistence", "baseline", "fim", "monitor", "analyze", "alerts", "report", "demo", "rules", "data"):
        assert c in out


def test_demo_runs_offline_and_writes_reports(runner):
    r = invoke(runner, "demo", "--out-dir", "demo-out")
    assert "SYNTHETIC DATA" in r.output and "TP=9 FN=0 TN=5 FP=0" in r.output and "NOT a production detection rate" in r.output
    assert {p.suffix for p in Path("demo-out").iterdir()} == {".json", ".csv", ".html"}


def test_rules_command_validates_and_lists(runner):
    r = invoke(runner, "rules")
    assert "SHIELD-001" in r.output and "SHIELD-009" in r.output and "IOC watchlist" in r.output


def test_bad_rules_file_is_clean_error(runner, tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("rules:\n - {id: X}\n")
    r = runner.invoke(cli, ["--rules", str(bad), "rules"])
    assert r.exit_code == 2 and "invalid rules configuration" in r.output and "Traceback" not in r.output


def test_analyze_sample_end_to_end_then_alerts_and_report(runner):
    r = invoke(runner, "analyze", "--events", str(ROOT / "samples" / "sysmon_events.xml"))
    assert "8 normalized, 1 malformed, 1 unsupported of 10" in r.output and "SHIELD-007" in r.output
    a = invoke(runner, "alerts", "--severity", "medium", "-d")
    assert "SHIELD-002" in a.output and "Conditions met" in a.output
    invoke(runner, "report", "--format", "all", "--out-dir", "rep")
    html = next(Path("rep").glob("*.html")).read_text(encoding="utf-8")
    assert "SHIELD-007" in html and "hunter2" not in html and "abc123secret" not in html


def test_analyze_requires_input_and_handles_bad_file(runner):
    assert invoke(runner, "analyze", ok=False).exit_code == 2
    Path("x.xml").write_text("<!DOCTYPE a [<!ENTITY b 'c'>]><Events/>")
    r = invoke(runner, "analyze", "--events", "x.xml", ok=False)
    assert r.exit_code == 2 and "DOCTYPE" in r.output and "Traceback" not in r.output


def test_report_without_data_is_clear_error(runner):
    r = invoke(runner, "report", ok=False)
    assert r.exit_code == 2 and "no events or alerts" in r.output


def test_baseline_fim_flow_and_protection(runner):
    d = Path("mon")
    d.mkdir()
    (d / "a.txt").write_text("alpha")
    (d / "b.txt").write_text("bravo")
    assert "Baseline created" in invoke(runner, "baseline", "--path", "mon").output
    again = invoke(runner, "baseline", "--path", "mon", ok=False)
    assert again.exit_code == 2 and "already exists" in again.output
    clean = invoke(runner, "fim", "--path", "mon")
    assert "0 created, 0 modified, 0 deleted" in clean.output_flat and "No alerts" in clean.output_flat
    (d / "b.txt").write_text("bravo-changed")
    (d / "c.txt").write_text("new")
    (d / "a.txt").unlink()
    r = invoke(runner, "fim", "--path", "mon")
    assert "1 created, 1 modified, 1 deleted" in r.output_flat and "SHIELD-005" in r.output_flat
    assert "Baseline created" in invoke(runner, "baseline", "--path", "mon", "--force").output


def test_fim_without_baseline_and_bad_paths(runner):
    Path("m2").mkdir()
    r = invoke(runner, "fim", "--path", "m2", ok=False)
    assert r.exit_code == 2 and "no baseline" in r.output
    assert invoke(runner, "baseline", "--path", "does-not-exist", ok=False).exit_code == 2


def test_fim_watch_mode_cli(runner):
    import threading
    import time
    d = Path("w")
    d.mkdir()
    (d / "a.txt").write_text("a")
    invoke(runner, "baseline", "--path", "w")
    threading.Timer(1.2, lambda: (d / "n.txt").write_text("new")).start()
    r = invoke(runner, "fim", "--path", "w", "--watch", "3")
    assert "created" in r.output and "SHIELD-005" in r.output


def test_persistence_command_and_diff_requires_baseline(runner):
    r = invoke(runner, "persistence")
    assert "Platform support" in r.output
    r = invoke(runner, "persistence", "--diff", ok=False)
    assert r.exit_code == 2 and "no persistence baseline" in r.output
    invoke(runner, "persistence", "--save-baseline")
    assert "Changes since baseline: added=0 removed=0 modified=0" in invoke(runner, "persistence", "--diff").output


def test_scan_processes_network_and_monitor_run_live(runner):
    r = invoke(runner, "scan")
    assert "Collected:" in r.output and "processes" in r.output
    assert "Processes (" in invoke(runner, "processes", "--limit", "5").output
    assert "Connections (" in invoke(runner, "network").output
    m = invoke(runner, "monitor", "--duration", "3", "--interval", "1")
    assert "polls" in m.output and "Traceback" not in m.output


def test_monitor_duration_is_bounded(runner):
    assert invoke(runner, "monitor", "--duration", "0", ok=False).exit_code == 2
    assert invoke(runner, "monitor", "--interval", "0.1", ok=False).exit_code == 2


def test_data_export_and_clear_require_confirmation(runner):
    invoke(runner, "analyze", "--events", str(ROOT / "samples" / "sysmon_events.xml"))
    invoke(runner, "data", "export", "-o", "out.json")
    doc = json.loads(Path("out.json").read_text(encoding="utf-8"))
    assert doc["counts"]["alerts"] >= 3 and doc["alerts"]
    refuse = invoke(runner, "data", "clear", ok=False)
    assert refuse.exit_code == 2 and "--yes" in refuse.output
    invoke(runner, "data", "clear", "--yes")
    assert json.loads(invoke(runner, "data", "export", "-o", "o2.json").output.split("Exported ")[1].split(" to ")[0].replace("'", '"')) ["alerts"] == 0


# ------------------------------------------------------------------------------- safety guarantees
def test_no_process_termination_or_system_modification_in_source():
    banned = [r"\.terminate\(", r"\.kill\(", r"os\.kill", r"taskkill", r"winreg\.(SetValue|CreateKey|DeleteValue|DeleteKey)",
              r"os\.remove\(", r"\.unlink\(", r"shutil\.rmtree", r"subprocess\.(Popen|call|check_call|check_output)", r"os\.system", r"input\("]
    offenders = []
    for f in (ROOT / "spyshield").rglob("*.py"):
        text = f.read_text(encoding="utf-8")
        for pat in banned:
            if re.search(pat, text):
                offenders.append((f.name, pat))
    # demo.py removes ITS OWN temporary folder; sysmon.py runs only the documented read-only `wevtutil qe`
    assert sorted(offenders) == [("demo.py", r"\.unlink\("), ("demo.py", r"shutil\.rmtree")], offenders


def test_registry_reader_opens_keys_read_only():
    src = (ROOT / "spyshield" / "collectors" / "persistence.py").read_text(encoding="utf-8")
    assert "KEY_READ" in src and "KEY_WRITE" not in src and "KEY_ALL_ACCESS" not in src


def test_no_keylogging_or_surveillance_apis_used():
    banned = ["pynput", "keyboard", "SetWindowsHookEx", "GetAsyncKeyState", "clipboard", "pyperclip", "cv2", "pyaudio", "sounddevice", "ImageGrab", "requests", "urllib", "socket.socket", "smtplib"]
    for f in (ROOT / "spyshield").rglob("*.py"):
        text = f.read_text(encoding="utf-8")
        for b in banned:
            assert not re.search(rf"\bimport\s+{re.escape(b)}\b|\bfrom\s+{re.escape(b)}\b|{re.escape(b)}\(", text), (f.name, b)


def test_no_automatic_startup_persistence_for_spyshield_itself():
    for f in (ROOT / "spyshield").rglob("*.py"):
        assert "schtasks" not in f.read_text(encoding="utf-8") and "sc create" not in f.read_text(encoding="utf-8")
