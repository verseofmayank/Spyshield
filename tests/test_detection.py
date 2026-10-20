"""Rule evaluation (matching and non-matching), correlation, dedupe, IOC, Sysmon parsing, demo accuracy."""
import copy
from pathlib import Path

import pytest

from spyshield.collectors import sysmon
from spyshield.core.config import Config, Rule, Watchlist, load_config
from spyshield.core.models import Event
from spyshield.demo import load_scenarios, metrics, run_all
from spyshield.detection.correlation import History
from spyshield.detection.engine import Engine
from tests.conftest import CHROME, EXPLORER, TEMP_EXE, at, fimev, net, persist, proc, rule_ids

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
BASE = [proc(0, "ex", 600, EXPLORER, ppid=500)]


def run(engine, events):
    return engine.process_batch(events)


# ------------------------------------------------------------------------------------ SHIELD-001
def test_temp_execution_alerts_low_with_context(engine):
    a = run(engine, BASE + [proc(5, "u", 800, TEMP_EXE, ppid=600, parent="ex")])
    assert rule_ids(a) == ["SHIELD-001"] and a[0].severity == "low" and "location only" in " ".join(a[0].conditions_met)
    assert a[0].status == "requires analyst review" and a[0].false_positives and a[0].investigation_steps


def test_ordinary_apps_outside_program_files_do_not_alert(engine):
    for image in (r"C:\Users\bob\AppData\Local\Programs\Foo\foo.exe", r"D:\Games\game.exe", r"C:\Users\bob\Downloads\setup.exe", CHROME, r"C:\Windows\System32\cmd.exe"):
        assert run(Engine(engine.config, Watchlist()), [proc(1, "p", 1, image)]) == [], image


def test_temp_exec_escalates_when_parent_is_document_host(engine):
    a = run(engine, [proc(0, "w", 10, r"C:\Program Files\Microsoft Office\WINWORD.EXE"), proc(5, "u", 11, TEMP_EXE, ppid=10, parent="w")])
    assert [x for x in a if x.rule_id == "SHIELD-001"][0].severity == "medium"


def test_allowlisted_temp_path_is_ignored(engine):
    assert run(engine, [proc(1, "c", 1, r"C:\Users\bob\AppData\Local\Temp\chocolatey\choco.exe")]) == []


def test_non_executable_extension_in_temp_is_ignored(engine):
    assert run(engine, [proc(1, "c", 1, r"C:\Users\bob\AppData\Local\Temp\notes.txt")]) == []


# ------------------------------------------------------------------------------------ names alone
@pytest.mark.parametrize("name", ["keylogger.exe", "SpyGlass-Recorder.exe", "screen_capture.exe", "hook_helper.exe", "xinput1_3.dll.exe"])
def test_suspicious_words_in_names_never_alert_by_themselves(engine, name):
    assert run(engine, [proc(1, "p", 1, rf"C:\Program Files\Vendor\{name}", cmd=f"{name} --record --capture")]) == []


@pytest.mark.parametrize("port", [22, 25, 53, 123, 5228, 8080, 8443, 49152, 65000])
def test_unusual_ports_never_alert(engine, port):
    ev = BASE + [proc(1, "p", 5, CHROME), net(10, "p", 5, "142.250.77.14", port)]
    assert run(engine, ev) == []


# ------------------------------------------------------------------------------------ SHIELD-002
def test_parent_child_match_and_nonmatch(engine):
    word = r"C:\Program Files\Microsoft Office\WINWORD.EXE"
    hit = run(engine, [proc(0, "w", 10, word), proc(5, "ps", 11, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", ppid=10, parent="w")])
    assert rule_ids(hit) == ["SHIELD-002"] and "lineage" in " ".join(hit[0].conditions_met)
    # same child under a normal parent: no alert
    ok = run(Engine(engine.config, Watchlist()), [proc(0, "e", 10, EXPLORER), proc(5, "ps", 11, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", ppid=10, parent="e")])
    assert ok == []
    # word launching a harmless child: no alert
    ok = run(Engine(engine.config, Watchlist()), [proc(0, "w", 10, word), proc(5, "n", 11, r"C:\Windows\System32\splwow64.exe", ppid=10, parent="w")])
    assert ok == []


def test_parent_found_via_ppid_when_no_explicit_key(engine):
    word = r"C:\Program Files\Microsoft Office\WINWORD.EXE"
    a = run(engine, [proc(0, "w", 10, word), proc(5, "cmd", 11, r"C:\Windows\System32\cmd.exe", ppid=10)])
    assert rule_ids(a) == ["SHIELD-002"]


def test_pid_reuse_does_not_create_false_parentage(engine):
    word = r"C:\Program Files\Microsoft Office\WINWORD.EXE"
    # Word (pid 10) exited; pid 10 was reused later by explorer-ish process; cmd started BEFORE reuse must not match the newer pid-10 process.
    ev = [proc(0, "w1", 10, word), proc(100, "w2", 10, EXPLORER), proc(50, "c", 11, r"C:\Windows\System32\cmd.exe", ppid=10)]
    a = run(engine, ev)
    assert [x for x in a if x.rule_id == "SHIELD-002"][0].evidence[0]["image"] == word
    # now cmd starts AFTER reuse, parent resolves to the explorer-like process: no alert
    ev = [proc(0, "w1", 10, word), proc(100, "w2", 10, EXPLORER), proc(150, "c", 11, r"C:\Windows\System32\cmd.exe", ppid=10)]
    assert not [x for x in run(Engine(engine.config, Watchlist()), ev) if x.rule_id == "SHIELD-002"]


def test_lineage_depth_and_cycles():
    h = History(100)
    a, b, c = proc(0, "a", 1, "a.exe"), proc(1, "b", 2, "b.exe", ppid=1, parent="a"), proc(2, "c", 3, "c.exe", ppid=2, parent="b")
    for e in (a, b, c):
        h.add(e)
    assert [e.image for e in h.lineage(c)] == ["b.exe", "a.exe"]
    a.parent_key = "c"  # corrupt cycle
    h.procs["a"].parent_key = "c"
    assert len(h.lineage(c)) <= 8


# ------------------------------------------------------------------------------------ SHIELD-003
def test_new_run_entry_alerts_and_escalates_on_suspicious_target(engine):
    a = run(engine, [persist(1, "added", "Helper", r'"C:\Users\Public\h.exe"', r"C:\Users\Public\h.exe")])
    assert rule_ids(a) == ["SHIELD-003"] and a[0].severity == "medium" and a[0].mitre[0]["id"] == "T1547.001"
    b = run(Engine(engine.config, Watchlist()), [persist(1, "added", "OneDrive", r'"C:\Program Files\OneDrive\od.exe"', r"C:\Program Files\OneDrive\od.exe")])
    assert b[0].severity == "low"


def test_removed_persistence_is_not_alerted(engine):
    assert run(engine, [persist(1, "removed", "Old", "x", "x")]) == []


def test_mitre_not_applied_to_non_windows_persistence(engine):
    a = run(engine, [persist(1, "added", "x.desktop", "/tmp/x.sh", "/tmp/x.sh", location="autostart:user:/home/u/.config/autostart")])
    assert a and a[0].mitre == []


# ------------------------------------------------------------------------------------ SHIELD-004
def test_process_plus_network_in_window_matches_and_outside_does_not(engine):
    start = proc(0, "u", 800, TEMP_EXE)
    assert rule_ids(run(engine, [start, net(60, "u", 800, "104.20.30.50", 443)])) == ["SHIELD-001", "SHIELD-004"]
    late = run(Engine(engine.config, Watchlist()), [proc(0, "u", 800, TEMP_EXE), net(400, "u", 800, "104.20.30.50", 443)])
    assert rule_ids(late) == ["SHIELD-001"]  # connection after the 300 s window
    priv = run(Engine(engine.config, Watchlist()), [proc(0, "u", 800, TEMP_EXE), net(60, "u", 800, "10.0.0.5", 443, cls="private")])
    assert rule_ids(priv) == ["SHIELD-001"]  # public_only
    normal = run(Engine(engine.config, Watchlist()), [proc(0, "c", 5, CHROME), net(10, "c", 5, "142.250.77.14", 443)])
    assert normal == []


def test_proc_net_alert_contains_both_observations(engine):
    a = [x for x in run(engine, [proc(0, "u", 800, TEMP_EXE), net(60, "u", 800, "104.20.30.50", 8443)]) if x.rule_id == "SHIELD-004"][0]
    assert [e["kind"] for e in a.evidence] == ["process_start", "network_connection"] and a.severity == "medium"
    assert "60s" in a.observation and a.process["image"] == TEMP_EXE


def test_connection_before_process_start_in_file_order_still_correlates(engine):
    ev = [net(60, "u", 800, "104.20.30.50", 443), proc(0, "u", 800, TEMP_EXE)]  # out-of-order input
    assert "SHIELD-004" in rule_ids(run(engine, ev))


def test_connection_without_known_start_cannot_correlate(engine):
    assert run(engine, [net(60, "ghost", 9, "104.20.30.50", 443)]) == []


def test_pid_reuse_connection_does_not_attach_to_old_process(engine):
    ev = [proc(0, "old", 50, TEMP_EXE), proc(1000, "new", 50, CHROME), net(1010, "new", 50, "104.20.30.50", 443)]
    assert "SHIELD-004" not in rule_ids(run(engine, ev))


# ------------------------------------------------------------------------------------ SHIELD-005
def test_fim_rules_and_path_severity(engine):
    a = run(engine, [fimev(1, "modified", r"C:\Windows\System32\drivers\etc\hosts", old_sha256="a" * 64, sha="b" * 64),
                     fimev(2, "created", r"D:\docs\new.txt")])
    sev = {x.observation.split(": ")[1]: x.severity for x in a}
    assert sev[r"C:\Windows\System32\drivers\etc\hosts"] == "high" and sev[r"D:\docs\new.txt"] == "low"
    assert "SHA-256 changed" in " ".join(a[0].conditions_met) or "SHA-256 changed" in " ".join(a[1].conditions_met)


def test_unchanged_baseline_produces_nothing(engine):
    assert run(engine, []) == []


# ------------------------------------------------------------------------------------ SHIELD-006
def conns(n, start=10, key="p", host_fmt="104.21.{}.5", step=1.0):
    return [net(start + i * step, key, 5, host_fmt.format(i), 443, lport=50000 + i) for i in range(n)]


def test_rate_rule_threshold_boundaries(engine):
    base = [proc(0, "p", 5, r"C:\Program Files\Sync\sync.exe")]
    assert run(engine, base + conns(25)) == []                              # exactly threshold: not exceeded
    a = run(Engine(engine.config, Watchlist()), base + conns(26))
    assert rule_ids(a) == ["SHIELD-006"] and "26 distinct destinations" in a[0].conditions_met[0] and a[0].severity == "low"


def test_rate_rule_window_expiry(engine):
    base = [proc(0, "p", 5, r"C:\Program Files\Sync\sync.exe")]
    assert run(engine, base + conns(40, step=5.0)) == []     # 40 destinations spread over 200 s: never >25 inside 60 s


def test_rate_rule_ignores_private_initial_and_repeated_sockets(engine):
    base = [proc(0, "p", 5, r"C:\Program Files\Sync\sync.exe")]
    priv = [net(10 + i, "p", 5, f"10.0.0.{i}", 445, cls="private", lport=50000 + i) for i in range(1, 60)]
    assert run(engine, base + priv) == []
    init = [net(10 + i, "p", 5, f"104.21.{i}.5", 443, lport=50000 + i, initial=True) for i in range(40)]
    assert run(Engine(engine.config, Watchlist()), base + init) == []
    same = [net(10 + i, "p", 5, "104.21.1.5", 443, lport=50000) for i in range(80)]  # same socket re-seen by polling
    assert run(Engine(engine.config, Watchlist()), base + same) == []


def test_rate_rule_allowlists(engine):
    chrome = [proc(0, "c", 5, CHROME)] + conns(40, key="c")
    assert run(engine, chrome) == []   # path-based ignore list


def test_rate_rule_connection_count_threshold(config):
    cfg = copy.deepcopy(config)
    r = cfg.rule("SHIELD-006")
    r.params = {"window_seconds": 60, "max_new_connections": 5, "public_only": True}
    eng = Engine(cfg, Watchlist())
    ev = [proc(0, "p", 5, r"C:\x\a.exe")] + [net(10 + i, "p", 5, "104.21.1.5", 443, lport=50000 + i) for i in range(8)]
    a = run(eng, ev)
    assert a and "new connections" in a[0].conditions_met[0]


# ------------------------------------------------------------------------------------ SHIELD-007
def sysmon_proc(t, guid, image, parent_guid=None, parent_image=None):
    return Event(at(t), "sysmon", "process_start", "h", guid, 1, None, parent_guid, image, None, parent_image, None, None, None, {"initial": False})


def sysmon_net(t, guid, ip="104.20.30.50", cls="public"):
    return Event(at(t), "sysmon", "network_connection", "h", guid, 1, None, None, None, None, None, None, None, None,
                 {"remote_ip": ip, "remote_port": 443, "remote_class": cls, "direction": "outbound", "state": "CONNECT"})


def test_sysmon_chain_correlates_by_guid(engine):
    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    word = r"C:\Program Files\Microsoft Office\WINWORD.EXE"
    ev = [sysmon_proc(0, "{W}", word), sysmon_proc(5, "{P}", ps, "{W}", word), sysmon_net(20, "{P}")]
    assert "SHIELD-007" in rule_ids(run(engine, ev))


def test_sysmon_chain_negatives(engine):
    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    word = r"C:\Program Files\Microsoft Office\WINWORD.EXE"
    # different GUID for the network event: no correlation
    ev = [sysmon_proc(0, "{W}", word), sysmon_proc(5, "{P}", ps, "{W}", word), sysmon_net(20, "{OTHER}")]
    assert "SHIELD-007" not in rule_ids(run(Engine(engine.config, Watchlist()), ev))
    # private destination
    ev = [sysmon_proc(0, "{W}", word), sysmon_proc(5, "{P}", ps, "{W}", word), sysmon_net(20, "{P}", "10.0.0.1", "private")]
    assert "SHIELD-007" not in rule_ids(run(Engine(engine.config, Watchlist()), ev))
    # outside window
    ev = [sysmon_proc(0, "{W}", word), sysmon_proc(5, "{P}", ps, "{W}", word), sysmon_net(5000, "{P}")]
    assert "SHIELD-007" not in rule_ids(run(Engine(engine.config, Watchlist()), ev))
    # powershell under explorer: not the configured chain
    ev = [sysmon_proc(0, "{E}", EXPLORER), sysmon_proc(5, "{P}", ps, "{E}", EXPLORER), sysmon_net(20, "{P}")]
    assert "SHIELD-007" not in rule_ids(run(Engine(engine.config, Watchlist()), ev))


def test_sysmon_chain_requires_sysmon_source(engine):
    # psutil-sourced events with the same shape must not trigger the Sysmon rule
    ev = [proc(0, "w", 10, r"C:\Program Files\Microsoft Office\WINWORD.EXE"), proc(5, "p", 11, r"C:\Windows\System32\cmd.exe", ppid=10, parent="w"), net(20, "p", 11, "104.20.30.50", 443)]
    assert "SHIELD-007" not in rule_ids(run(engine, ev))


def test_analyst_defined_chain(config):
    cfg = copy.deepcopy(config)
    cfg.rule("SHIELD-007").params["chains"] = [{"name": "custom", "image_regex": "(?i)mytool\\.exe$", "require_public_connection": True}]
    ev = [sysmon_proc(0, "{A}", r"C:\x\mytool.exe"), sysmon_net(10, "{A}")]
    a = run(Engine(cfg, Watchlist()), ev)
    assert "SHIELD-007" in rule_ids(a) and "custom" in a[0].observation + str([x.observation for x in a])


# ------------------------------------------------------------------------------------ SHIELD-008
def test_persistence_then_execution_both_orders_and_negatives(engine):
    target = r"C:\Users\Public\r.exe"
    p = persist(10, "added", "Upd", f'"{target}"', target)
    s = proc(300, "r", 99, target)
    a = run(engine, [p, s])
    h = [x for x in a if x.rule_id == "SHIELD-008"]
    assert h and h[0].severity == "high" and [e["kind"] for e in h[0].evidence] == ["persistence_change", "process_start"]
    # the engine must also fire when the process event is ingested first by arrival but sorts later (batch sorts by time)
    assert "SHIELD-008" in rule_ids(run(Engine(engine.config, Watchlist()), [s, p]))
    # execution BEFORE the entry is not "subsequent execution"
    early = run(Engine(engine.config, Watchlist()), [proc(1, "r", 99, target), persist(100, "added", "Upd", target, target)])
    assert "SHIELD-008" not in rule_ids(early)
    # different path
    other = run(Engine(engine.config, Watchlist()), [p, proc(300, "o", 98, r"C:\Users\Public\other.exe")])
    assert "SHIELD-008" not in rule_ids(other)
    # outside the 24 h window
    late = run(Engine(engine.config, Watchlist()), [p, proc(10 + 90000, "r", 99, target)])
    assert "SHIELD-008" not in rule_ids(late)


def test_persistence_exec_normal_path_is_medium_not_high(engine):
    t = r"C:\Program Files\App\app.exe"
    a = run(engine, [persist(0, "added", "App", t, t), proc(30, "a", 7, t)])
    assert [x for x in a if x.rule_id == "SHIELD-008"][0].severity == "medium"


# ------------------------------------------------------------------------------------ IOC
def test_ioc_hash_ip_path_name_exact_matches(engine_ioc):
    h = "0" * 63 + "1"
    a = run(engine_ioc, [proc(1, "a", 1, r"C:\Program Files\X\x.exe", sha=h),
                         net(2, "a", 1, "203.0.113.66", 443, cls="private"),
                         proc(3, "b", 2, r"C:\Tools\demo-bad-tool.exe"),
                         fimev(4, "created", r"C:\ProgramData\demo-implant\x.dll")])
    kinds = sorted(x.observation.split("(")[1].split(")")[0] for x in a if x.rule_id == "SHIELD-009")
    assert kinds == ["image_name", "ip", "path", "sha256"]
    assert all("not proof" in x.observation and any("watchlist source" in c for c in x.conditions_met) for x in a if x.rule_id == "SHIELD-009")


def test_ioc_near_misses_do_not_match(engine_ioc):
    a = run(engine_ioc, [proc(1, "a", 1, r"C:\Program Files\X\x.exe", sha="0" * 63 + "2"), net(2, "a", 1, "203.0.113.67", 443),
                         proc(3, "b", 2, r"C:\Tools\demo-bad-tool2.exe")])
    assert not [x for x in a if x.rule_id == "SHIELD-009"]


def test_empty_watchlist_never_alerts(engine):
    assert run(engine, [proc(1, "a", 1, r"C:\x\x.exe", sha="0" * 63 + "1")]) == []


# ------------------------------------------------------------------------------------ dedupe / cooldown / bounds
def test_alert_deduplication_and_cooldown(engine):
    ev = [proc(0, "u", 8, TEMP_EXE), persist(1, "added", "x", "x", "x")]
    first = run(engine, [proc(0, "u", 8, TEMP_EXE)])
    assert len(first) == 1
    again = engine.ingest(proc(10, "u", 8, TEMP_EXE))      # same subject within cooldown
    assert again == [] and engine.alerts[0].suppressed_count == 1 and engine.stats["suppressed"] == 1
    later = engine.ingest(proc(10 + 400, "u", 8, TEMP_EXE))  # cooldown (300 s) elapsed
    assert len(later) == 1 and len(engine.alerts) == 2


def test_distinct_subjects_are_not_merged(engine):
    a = run(engine, [proc(0, "u1", 8, TEMP_EXE), proc(1, "u2", 9, TEMP_EXE)])
    assert len(a) == 2


def test_alert_schema_fields(engine):
    a = run(engine, [proc(0, "u", 8, TEMP_EXE, cmd="upd.exe --x")])[0].to_dict()
    for k in ("alert_id", "rule_id", "title", "severity", "ts", "host", "process", "evidence", "conditions_met", "confidence", "limitations",
              "mitre", "investigation_steps", "status", "false_positives"):
        assert k in a
    assert a["ts"].endswith("Z") and a["alert_id"].startswith("A-")


def test_history_is_bounded():
    h = History(max_events=50)
    for i in range(500):
        h.add(proc(i, f"k{i}", i, "a.exe"))
    assert len(h.procs) <= 50 and h.dropped == 450


def test_polling_limitation_is_stated_on_polled_alerts(engine):
    a = run(engine, [proc(0, "u", 8, TEMP_EXE, source="psutil")])
    assert "polling" in a[0].limitations.lower()


def test_disabled_rule_is_skipped(config):
    cfg = copy.deepcopy(config)
    cfg.rule("SHIELD-001").enabled = False
    assert run(Engine(cfg, Watchlist()), [proc(0, "u", 8, TEMP_EXE)]) == []


def test_alert_timestamps_are_utc_and_sorted_batch(engine):
    a = run(engine, [net(60, "u", 800, "104.20.30.50", 443), proc(0, "u", 800, TEMP_EXE)])
    assert all(x.ts.tzinfo is not None and x.ts.utcoffset().total_seconds() == 0 for x in a)


# ------------------------------------------------------------------------------------ Sysmon parsing
def test_parse_sample_export():
    evs, rep = sysmon.parse_file(SAMPLES / "sysmon_events.xml")
    assert (rep.total, rep.parsed, rep.malformed, rep.skipped_unsupported) == (10, 8, 1, 1)
    assert rep.by_event_id[7] == 1 and rep.by_event_id[1] == 3
    ps = [e for e in evs if e.kind == "process_start" and e.name == "powershell.exe"][0]
    assert ps.proc_key == "{11111111-0000-0000-0000-000000000003}" and ps.parent_key.endswith("0002}") and ps.pid == 1010
    assert "hunter2" not in ps.cmdline and "abc123secret" not in ps.cmdline
    n = [e for e in evs if e.kind == "network_connection"][0]
    assert n.data["remote_ip"] == "104.20.30.50" and n.data["remote_class"] == "public" and n.data["direction"] == "outbound" and n.proc_key == ps.proc_key
    assert n.ts.tzinfo is not None and n.ts.microsecond == 250000
    assert {e.kind for e in evs} >= {"process_start", "network_connection", "process_end", "file_change", "persistence_change", "dns_query"}
    reg = [e for e in evs if e.kind == "persistence_change"][0]
    assert reg.data["target_path"] == r"C:\Users\Public\runner_sim.exe" and reg.data["is_run_key"]


def test_sysmon_hash_extraction():
    evs, _ = sysmon.parse_file(SAMPLES / "sysmon_events.xml")
    assert evs[0].sha256 == "AAAA000000000000000000000000000000000000000000000000000000000001"


def test_malformed_events_are_counted_not_guessed():
    evs, rep = sysmon.parse_file(SAMPLES / "sysmon_malformed.xml")
    assert rep.parsed == 2 and rep.malformed == 5 and len(rep.problems) == 5
    assert {e.kind for e in evs} == {"process_start", "network_connection"}  # the valid ones after broken fragments survive


@pytest.mark.parametrize("xml", ["", "not xml at all", "<Events></Events>"])
def test_empty_or_garbage_input(xml):
    evs, rep = sysmon.parse_text(xml)
    assert evs == [] and rep.parsed == 0


def test_xxe_and_entity_expansion_rejected():
    with pytest.raises(ValueError, match="DOCTYPE"):
        sysmon.parse_text('<!DOCTYPE x [<!ENTITY a "aaaa">]><Events></Events>')


def test_missing_file_and_oversize(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="cannot read"):
        sysmon.parse_file(tmp_path / "nope.xml")
    big = tmp_path / "big.xml"
    big.write_text("<Events/>")
    monkeypatch.setattr(sysmon, "MAX_FILE_BYTES", 3)
    with pytest.raises(ValueError, match="larger than"):
        sysmon.parse_file(big)


def test_out_of_order_export_correlates_after_sorting():
    evs, _ = sysmon.parse_file(SAMPLES / "sysmon_events.xml")
    assert evs[1].kind == "network_connection" and evs[1].ts > evs[2].ts  # file order is NOT time order
    a = Engine(load_config(), Watchlist()).process_batch(evs)
    assert {"SHIELD-002", "SHIELD-003", "SHIELD-007"} <= set(rule_ids(a))


def test_live_sysmon_missing_is_a_clear_error(monkeypatch):
    import subprocess
    monkeypatch.setattr(sysmon.sys, "platform", "win32")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: type("R", (), {"returncode": 15007, "stdout": "", "stderr": "The specified channel could not be found."})())
    with pytest.raises(RuntimeError, match="Sysmon may not be installed"):
        sysmon.read_live()
    monkeypatch.setattr(sysmon.sys, "platform", "linux")
    with pytest.raises(RuntimeError, match="only available on Windows"):
        sysmon.read_live()


# ------------------------------------------------------------------------------------ labelled synthetic evaluation
def test_all_labelled_scenarios_match_expectations():
    results = run_all(load_config(), load_config and __import__("spyshield.core.config", fromlist=["load_watchlist"]).load_watchlist())
    bad = [(r.id, r.label, r.expected, r.got) for r in results if r.outcome in ("FN", "FP")]
    assert bad == []
    m = metrics(results)
    assert m["TP"] == 9 and m["TN"] == 5 and m["FP"] == 0 and m["FN"] == 0 and "NOT a production detection rate" in m["caveat"]


def test_scenario_file_covers_required_cases():
    ids = {s["id"] for s in load_scenarios()["scenarios"]}
    assert len(ids) >= 14 and sum(s["label"] == "benign" for s in load_scenarios()["scenarios"]) >= 5
