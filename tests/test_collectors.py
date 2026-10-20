"""Process, network, persistence and FIM collectors, plus redaction, config and storage."""
import hashlib
import os
import platform
import sqlite3
from types import SimpleNamespace as NS

import psutil
import pytest

from spyshield.collectors import filesystem, network, persistence, processes
from spyshield.core.config import ConfigError, Config, load_config, load_watchlist, validate
from spyshield.core.models import Alert, Event, parse_ts
from spyshield.core.pathutil import extract_target_path, matches_any, norm
from spyshield.core.redact import REDACTED, redact
from spyshield.core.storage import BaselineExists, Storage
from tests.conftest import at, fimev


# ----------------------------------------------------------------------------------- process collector
class FakeProc:
    def __init__(self, pid, ppid=1, name="a.exe", exe=r"C:\a\a.exe", ct=1000.0, user="u", cmd=("a.exe",), deny=()):
        self.pid, self._v, self._deny = pid, dict(ppid=ppid, name=name, exe=exe, create_time=ct, username=user, status="running",
                                                  cmdline=list(cmd), cpu_times=NS(user=1.0, system=0.5), memory_info=NS(rss=1234)), set(deny)

    def oneshot(self):
        import contextlib
        return contextlib.nullcontext()

    def __getattr__(self, attr):
        if attr.startswith("_"):
            raise AttributeError(attr)

        def f():
            if attr in self._deny:
                raise psutil.AccessDenied(self.pid)
            return self._v[attr]
        return f


def snap(*procs):
    return processes.snapshot(lambda: list(procs))


def test_snapshot_normalises_metadata():
    p = snap(FakeProc(10, 4, "Chrome.exe", r"C:\Program Files\Chrome\chrome.exe", 5000.0, "DOM\\bob", ("chrome.exe", "--x")))[0]
    assert (p.pid, p.ppid, p.name, p.exe, p.username, p.key) == (10, 4, "Chrome.exe", r"C:\Program Files\Chrome\chrome.exe", "DOM\\bob", "10:5000")
    assert p.cmdline == "chrome.exe --x" and p.cpu_seconds == 1.5 and p.rss == 1234 and not p.access_limited


def test_access_denied_is_graceful_and_flagged():
    p = snap(FakeProc(4, deny={"exe", "username", "cmdline"}))[0]
    assert p.exe is None and p.username is None and p.cmdline is None and p.access_limited and p.name == "a.exe"


def test_vanished_process_is_skipped():
    class Gone(FakeProc):
        def oneshot(self):
            raise psutil.NoSuchProcess(1)
    assert snap(Gone(1), FakeProc(2))[0].pid == 2


def test_cmdline_secrets_redacted_at_collection():
    p = snap(FakeProc(1, cmd=("tool.exe", "--password=hunter2", "--token", "abcDEF123456", "https://u:pw@host/x")))[0]
    assert "hunter2" not in p.cmdline and "abcDEF123456" not in p.cmdline and "u:pw@" not in p.cmdline and REDACTED in p.cmdline


@pytest.mark.parametrize("raw,leaked", [
    ("run.exe -p secretpass --password secretpass2", ["secretpass2"]),
    ("curl -H 'Authorization: Bearer abcdefghijklmnop12345' x", ["abcdefghijklmnop12345"]),
    ("x --api-key=AKIAABCDEFGHIJKLMNOP", ["AKIAABCDEFGHIJKLMNOP"]),
    ("tool token=ghp_" + "a" * 36, ["ghp_aaaa"]),
    ("app /pwd:Sup3rSecret", ["Sup3rSecret"]),
])
def test_redaction(raw, leaked):
    out = redact(raw)
    assert all(l not in out for l in leaked)


def test_redaction_truncates_and_keeps_normal_text():
    assert redact("notepad.exe C:\\docs\\a.txt") == "notepad.exe C:\\docs\\a.txt"
    assert redact("x" * 5000).endswith("[truncated]") and len(redact("x" * 5000)) < 1100


def test_tracker_start_end_and_initial_flag():
    tr = processes.ProcessTracker(host="h")
    ev1 = tr.update(snap(FakeProc(1, 0, "a.exe", ct=100.0), FakeProc(2, 1, "b.exe", ct=200.0)), at(1000))
    assert [e.kind for e in ev1] == ["process_start", "process_start"] and all(e.data["initial"] for e in ev1)
    ev2 = tr.update(snap(FakeProc(1, 0, "a.exe", ct=100.0), FakeProc(3, 1, "c.exe", ct=900.0)), at(1001))
    kinds = sorted((e.kind, e.pid) for e in ev2)
    assert kinds == [("process_end", 2), ("process_start", 3)]
    assert not [e for e in ev2 if e.kind == "process_start"][0].data["initial"]


def test_pid_reuse_creates_new_identity():
    tr = processes.ProcessTracker(host="h")
    tr.update(snap(FakeProc(50, 1, "old.exe", ct=100.0)), at(1000))
    ev = tr.update(snap(FakeProc(50, 1, "new.exe", ct=500.0)), at(1001))
    assert sorted((e.kind, e.name) for e in ev) == [("process_end", "old.exe"), ("process_start", "new.exe")]
    assert ev[0].proc_key != ev[1].proc_key


def test_parent_must_be_older_than_child_pid_reuse_guard():
    tr = processes.ProcessTracker(host="h")
    # PPID 7 now belongs to a process created AFTER the child, so it cannot be the real parent.
    evs = tr.update(snap(FakeProc(7, 0, "newer.exe", ct=900.0), FakeProc(8, 7, "child.exe", ct=500.0)), at(1000))
    child = [e for e in evs if e.pid == 8][0]
    assert child.parent_key is None and child.ppid == 7
    evs = processes.ProcessTracker(host="h").update(snap(FakeProc(7, 0, "parent.exe", ct=100.0), FakeProc(8, 7, "child.exe", ct=500.0)), at(1000))
    assert [e for e in evs if e.pid == 8][0].parent_key == "7:100"


def test_process_start_time_is_creation_time_not_observation_time():
    ev = processes.ProcessTracker(host="h").update(snap(FakeProc(1, 0, ct=1_000_000.0)), at(5_000_000))[0]
    assert ev.ts.timestamp() == 1_000_000.0


def test_hash_is_opt_in_and_size_limited(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"hello")
    assert processes.sha256_file(str(f), 1024) == (hashlib.sha256(b"hello").hexdigest(), None)
    h, why = processes.sha256_file(str(f), 2)
    assert h is None and "limit" in why
    assert processes.sha256_file(str(tmp_path), 1024)[0] is None
    assert processes.sha256_file(str(tmp_path / "missing"), 1024)[1].startswith("unreadable")
    tr = processes.ProcessTracker(host="h")
    assert tr.update(snap(FakeProc(1, exe=str(f))), at(1))[0].sha256 is None
    tr = processes.ProcessTracker(hash_executables=True, host="h")
    assert tr.update(snap(FakeProc(1, exe=str(f))), at(1))[0].sha256 == hashlib.sha256(b"hello").hexdigest()


# ------------------------------------------------------------------------------------ network collector
@pytest.mark.parametrize("ip,cls", [("8.8.8.8", "public"), ("10.1.2.3", "private"), ("192.168.0.9", "private"), ("127.0.0.1", "loopback"), ("::1", "loopback"),
                                    ("169.254.1.1", "reserved"), ("224.0.0.1", "reserved"), ("0.0.0.0", "unspecified"), ("100.64.0.1", "private"),
                                    ("2606:4700::1111", "public"), ("fe80::1", "reserved"), ("fd00::1", "private"), ("::ffff:127.0.0.1", "loopback"),
                                    ("garbage", "invalid"), (None, "invalid")])
def test_classify_ip(ip, cls):
    assert network.classify_ip(ip) == cls


def conn(pid, rip, rport, status="ESTABLISHED", lip="10.0.0.5", lport=40000, type_=1):
    return NS(pid=pid, raddr=NS(ip=rip, port=rport) if rip else (), laddr=NS(ip=lip, port=lport), status=status, type=type_)


def test_connections_attributed_to_processes():
    procs = snap(FakeProc(10, name="chrome.exe", exe="c:/chrome.exe", ct=100.0))
    evs, st = network.collect(procs, now=at(5), connections=lambda: [conn(10, "8.8.8.8", 443), conn(99, "1.1.1.1", 53), conn(10, None, 0, "LISTEN"), conn(10, "8.8.4.4", 80, "TIME_WAIT")])
    assert st == {"total": 2, "attributed": 1, "unattributed": 1, "denied": False}
    a = [e for e in evs if e.pid == 10][0]
    assert a.proc_key == "10:100" and a.name == "chrome.exe" and a.data["remote_class"] == "public" and a.data["protocol"] == "tcp"
    u = [e for e in evs if e.pid == 99][0]
    assert u.proc_key is None  # unattributed, never guessed


def test_connection_table_denied_is_reported():
    def deny():
        raise psutil.AccessDenied()
    evs, st = network.collect([], connections=deny)
    assert evs == [] and st["denied"] is True


def test_initial_flag_marks_preexisting_connections():
    evs, _ = network.collect(snap(FakeProc(1)), connections=lambda: [conn(1, "8.8.8.8", 443)], initial=True)
    assert evs[0].data["initial"] is True


def test_live_collectors_run_on_this_machine():
    """Real psutil calls: must not raise and must return plausible data (no assumptions about what is running)."""
    procs = processes.snapshot()
    assert any(p.pid == os.getpid() for p in procs)
    evs, st = network.collect(procs)
    assert st["total"] >= 0 and all(e.kind == "network_connection" for e in evs)


# ------------------------------------------------------------------------------------------ persistence
RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"


def reg(*items):
    vals = {}
    for hive, key, name, data in items:
        vals.setdefault((hive, key), []).append((name, data))
    return persistence.FakeRegistry(vals)


def test_target_path_extraction():
    assert extract_target_path(r'"C:\Program Files\App\app.exe" --flag') == r"C:\Program Files\App\app.exe"
    assert extract_target_path(r"C:\Tools\run.exe /silent") == r"C:\Tools\run.exe"
    assert extract_target_path(r"C:\Program Files\App\a b.exe -x") == r"C:\Program Files\App\a b.exe"
    assert extract_target_path("") is None and extract_target_path(None) is None


def test_registry_snapshot_and_diff():
    base = persistence.snapshot_windows(reg(("HKCU", RUN, "OneDrive", r'"C:\OneDrive\od.exe" /bg'), ("HKCU", RUN, "Old", r"C:\old.exe")), folders=[])
    cur = persistence.snapshot_windows(reg(("HKCU", RUN, "OneDrive", r'"C:\OneDrive\od.exe" /bg --new'), ("HKCU", RUN, "New", r'"C:\Users\Public\n.exe"')), folders=[])
    d = persistence.diff(base, cur)
    assert [e["name"] for e in d["added"]] == ["New"] and [e["name"] for e in d["removed"]] == ["Old"]
    assert [e["name"] for e in d["modified"]] == ["OneDrive"] and "--new" in d["modified"][0]["command"] and "/bg" in d["modified"][0]["old_command"]
    assert d["added"][0]["target_path"] == r"C:\Users\Public\n.exe"


def test_unchanged_snapshot_has_no_diff():
    s = persistence.snapshot_windows(reg(("HKLM", RUN, "A", r"C:\a.exe")), folders=[])
    assert persistence.diff(s, s) == {"added": [], "removed": [], "modified": []}


def test_inaccessible_keys_are_reported_not_fatal():
    s = persistence.snapshot_windows(reg(("HKCU", RUN, "A", r"C:\a.exe")), folders=[])
    assert any("HKLM" in u for u in s["unreadable"]) and len(s["entries"]) == 1


def test_registry_secrets_redacted_in_command():
    s = persistence.snapshot_windows(reg(("HKCU", RUN, "A", r"C:\a.exe --password=hunter2")), folders=[])
    assert "hunter2" not in str(s)


def test_startup_folder_change_detection(tmp_path):
    f = tmp_path / "Startup"
    f.mkdir()
    (f / "desktop.ini").write_text("x")
    (f / "tool.lnk").write_text("x")
    base = persistence.snapshot_windows(reg(), folders=[("StartupFolder:User", f)])
    assert len(base["entries"]) == 1  # desktop.ini ignored
    (f / "evil_sim.bat").write_text("echo demo")
    cur = persistence.snapshot_windows(reg(), folders=[("StartupFolder:User", f)])
    d = persistence.diff(base, cur)
    assert [e["name"] for e in d["added"]] == ["evil_sim.bat"] and d["added"][0]["target_path"].endswith("evil_sim.bat")
    (f / "tool.lnk").unlink()
    assert [e["name"] for e in persistence.diff(cur, persistence.snapshot_windows(reg(), folders=[("StartupFolder:User", f)]))["removed"]] == ["tool.lnk"]


def test_changes_to_events_include_metadata_not_contents(tmp_path):
    exe = tmp_path / "run.exe"
    exe.write_bytes(b"MZ-demo")
    s = persistence.snapshot_windows(reg(("HKCU", RUN, "X", str(exe))), folders=[])
    evs = persistence.changes_to_events(persistence.diff({"entries": {}}, s))
    meta = evs[0].data["target_meta"]
    assert meta["exists"] and meta["size"] == 7 and meta["sha256"] == hashlib.sha256(b"MZ-demo").hexdigest() and "MZ-demo" not in str(evs[0].to_dict())
    assert persistence.target_metadata(str(tmp_path / "nope.exe")) == {"exists": False}


def test_linux_autostart(tmp_path):
    d = tmp_path / ".config" / "autostart"
    d.mkdir(parents=True)
    (d / "x.desktop").write_text("[Desktop Entry]\nExec=/tmp/x.sh --demo\n")
    s = persistence.snapshot_linux(tmp_path)
    assert s["platform"] == "linux" and list(s["entries"].values())[0]["target_path"] == "/tmp/x.sh"


@pytest.mark.parametrize("sysname,expect", [("Windows", "full"), ("Linux", "partial"), ("Darwin", "unsupported")])
def test_platform_support_reporting(monkeypatch, sysname, expect):
    monkeypatch.setattr(platform, "system", lambda: sysname)
    assert expect in persistence.supported()["support"]
    if sysname == "Darwin":
        s = persistence.snapshot()
        assert s["entries"] == {} and s["unsupported"] is True  # honest: unsupported, not "nothing found"


@pytest.mark.skipif(os.name != "nt", reason="real Registry read is Windows-only")
def test_real_registry_read_is_read_only_and_works():
    s = persistence.snapshot_windows()
    assert s["platform"] == "windows" and isinstance(s["entries"], dict)


# ------------------------------------------------------------------------------------------------ FIM
def mkdir_files(tmp_path, files):
    for n, c in files.items():
        p = tmp_path / n
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(c)
    return str(tmp_path.resolve())


def test_hash_and_metadata(tmp_path):
    root = mkdir_files(tmp_path, {"a.txt": "alpha"})
    files, st = filesystem.scan_directory(root)
    assert files["a.txt"]["sha256"] == hashlib.sha256(b"alpha").hexdigest() and files["a.txt"]["size"] == 5 and st["scanned"] == 1


def test_create_modify_delete_detected(tmp_path):
    root = mkdir_files(tmp_path, {"a.txt": "a", "b.txt": "b", "c.txt": "c"})
    base, _ = filesystem.scan_directory(root)
    (tmp_path / "b.txt").write_text("B-changed")
    (tmp_path / "c.txt").unlink()
    (tmp_path / "d.txt").write_text("new")
    d = filesystem.compare(base, filesystem.scan_directory(root)[0])
    assert [r["relpath"] for r in d["created"]] == ["d.txt"] and [r["relpath"] for r in d["modified"]] == ["b.txt"] and [r["relpath"] for r in d["deleted"]] == ["c.txt"]
    assert d["modified"][0]["basis"] == "sha256"
    evs = filesystem.changes_to_events(root, d, now=at(1), host="h")
    assert {e.data["change"] for e in evs} == {"created", "modified", "deleted"} and all(e.kind == "file_change" for e in evs)


def test_unchanged_files_produce_no_changes(tmp_path):
    root = mkdir_files(tmp_path, {"a.txt": "a", "sub/b.txt": "b"})
    base, _ = filesystem.scan_directory(root)
    assert filesystem.compare(base, filesystem.scan_directory(root)[0]) == {"created": [], "modified": [], "deleted": []}


def test_exclusions_and_nested(tmp_path):
    root = mkdir_files(tmp_path, {"a.txt": "a", "x.log": "log", "sub/y.log": "log", "sub/z.txt": "z"})
    files, st = filesystem.scan_directory(root, exclude=["*.log"])
    assert sorted(files) == ["a.txt", "sub/z.txt"] and st["excluded"] == 2


def test_size_limit_records_metadata_only_and_compares_by_size_mtime(tmp_path):
    root = mkdir_files(tmp_path, {"big.bin": "x" * 100})
    base, st = filesystem.scan_directory(root, max_file_bytes=10)
    assert base["big.bin"]["sha256"] is None and "limit" in base["big.bin"]["hash_skipped"] and st["hash_skipped"] == 1
    (tmp_path / "big.bin").write_text("y" * 150)
    d = filesystem.compare(base, filesystem.scan_directory(root, max_file_bytes=10)[0])
    assert d["modified"][0]["basis"].startswith("size/mtime")


def test_file_count_limit(tmp_path):
    root = mkdir_files(tmp_path, {f"f{i}.txt": str(i) for i in range(10)})
    files, st = filesystem.scan_directory(root, max_files=4)
    assert len(files) == 4 and st["truncated"] is True


def test_symlinks_are_not_followed_and_loops_are_safe(tmp_path):
    root = mkdir_files(tmp_path, {"real/a.txt": "a"})
    try:
        os.symlink(str(tmp_path / "real"), str(tmp_path / "loop_to_real"), target_is_directory=True)
        os.symlink(str(tmp_path), str(tmp_path / "real" / "back_to_root"), target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted here")
    files, st = filesystem.scan_directory(root)
    assert st["symlinks"] == 2 and files["loop_to_real"]["is_symlink"] and files["loop_to_real"]["sha256"] is None
    assert sorted(f for f in files if not files[f]["is_symlink"]) == ["real/a.txt"]  # nothing double-counted through links


def test_inaccessible_entries_are_counted_not_fatal(tmp_path, monkeypatch):
    root = mkdir_files(tmp_path, {"ok.txt": "ok", "locked/secret.txt": "s"})
    real = os.scandir

    def flaky(path):
        if str(path).endswith("locked"):
            raise PermissionError("denied")
        return real(path)
    monkeypatch.setattr(os, "scandir", flaky)
    files, st = filesystem.scan_directory(root)
    assert "ok.txt" in files and st["unreadable"] == 1


def test_unreadable_file_hash_is_reported(tmp_path, monkeypatch):
    root = mkdir_files(tmp_path, {"a.txt": "a"})
    monkeypatch.setattr(filesystem, "sha256_file", lambda p, m: (None, "unreadable (PermissionError)"))
    files, st = filesystem.scan_directory(root)
    assert files["a.txt"]["hash_skipped"].startswith("unreadable") and st["unreadable"] == 1


def test_resolve_root_refuses_bad_targets(tmp_path):
    with pytest.raises(filesystem.FimError, match="does not exist"):
        filesystem.resolve_root(str(tmp_path / "nope"))
    f = tmp_path / "file.txt"
    f.write_text("x")
    with pytest.raises(filesystem.FimError, match="not a directory"):
        filesystem.resolve_root(str(f))
    with pytest.raises(filesystem.FimError, match="root"):
        filesystem.resolve_root(os.path.abspath(os.sep))


def test_fim_events_never_contain_file_contents(tmp_path):
    root = mkdir_files(tmp_path, {"secret.txt": "TOP-SECRET-CONTENT"})
    base, _ = filesystem.scan_directory(root)
    (tmp_path / "secret.txt").write_text("TOP-SECRET-CONTENT-2")
    evs = filesystem.changes_to_events(root, filesystem.compare(base, filesystem.scan_directory(root)[0]))
    assert "TOP-SECRET" not in str([e.to_dict() for e in evs])


def test_watch_mode_sees_real_changes(tmp_path):
    root = str(tmp_path.resolve())
    got = []
    import threading
    import time
    th = threading.Thread(target=lambda: filesystem.watch(root, got.append, duration=3.0))
    th.start()
    time.sleep(1.0)
    (tmp_path / "w.txt").write_text("hello")
    time.sleep(0.5)
    (tmp_path / "w.txt").write_text("hello2")
    th.join()
    assert any(e.data["change"] == "created" and e.data["path"].endswith("w.txt") for e in got)
    assert any(e.data["change"] == "modified" for e in got) and all(e.source == "fim" for e in got)


# ---------------------------------------------------------------------------------------- config / IOC
def test_default_rules_load_and_validate(config):
    assert {r.id for r in config.rules} >= {f"SHIELD-00{i}" for i in range(1, 10)}
    for r in config.rules:
        assert r.false_positives and r.action and r.title and r.description and r.telemetry


def test_validation_reports_every_problem():
    errs = validate({"rules": [
        {"id": "X", "title": "t", "description": "d", "type": "nope", "severity": "critical", "telemetry": ["process", "bogus"], "false_positives": ["f"], "action": ["a"]},
        {"id": "X", "title": "t2", "description": "d", "type": "outbound_rate", "severity": "low", "telemetry": ["network"], "false_positives": ["f"], "action": ["a"], "params": {"window_seconds": -1}},
        {"id": "Y", "title": "t", "description": "d", "type": "persistence_change", "severity": "low", "telemetry": ["persistence"], "false_positives": ["f"], "action": ["a"], "mitre": [{"id": "T-bad"}]},
        {"id": "Z"}], "settings": {"poll_interval_seconds": 0.1, "unknown_setting": 1}})
    text = "\n".join(errs)
    for needle in ("unknown type", "severity must be", "telemetry must be", "duplicate rule id", "window_seconds", "invalid MITRE", "missing required field", "poll_interval_seconds", "unknown_setting"):
        assert needle in text, needle


def test_bad_files_raise_configerror(tmp_path):
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path / "missing.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("rules: [unclosed")
    with pytest.raises(ConfigError, match="not valid YAML"):
        load_config(bad)
    bad.write_text("rules: []")
    with pytest.raises(ConfigError):
        load_config(bad)


def test_regex_in_chain_validated():
    errs = validate({"rules": [{"id": "S", "title": "t", "description": "d", "type": "sysmon_chain", "severity": "low", "telemetry": ["sysmon"],
                                "false_positives": ["f"], "action": ["a"], "params": {"window_seconds": 5, "chains": [{"image_regex": "(unclosed"}]}}]})
    assert any("not a valid regex" in e for e in errs)


def test_watchlist_validation(tmp_path):
    wl = load_watchlist()
    assert len(wl.hashes) == 1 and "203.0.113.66" in wl.ips and wl.source and wl.updated
    bad = tmp_path / "ioc.yaml"
    bad.write_text("indicators:\n - {type: sha256, value: nothex}\n - {type: ip, value: 999.1.1.1}\n - {type: wat, value: x}\n")
    with pytest.raises(ConfigError) as e:
        load_watchlist(bad)
    assert "sha256" in str(e.value) and "ip" in str(e.value) and "unknown indicator type" in str(e.value)
    assert load_watchlist(None).empty() is False


def test_path_matching_is_case_and_slash_insensitive():
    assert matches_any(r"C:\Users\Bob\AppData\Local\Temp\a.exe", ["*/appdata/local/temp/*"])
    assert matches_any("/TMP/x", ["/tmp/*"]) and not matches_any(r"C:\Program Files\a.exe", ["*/appdata/local/temp/*"])
    assert norm('"C:\\A\\B\\"') == "c:/a/b"


# ---------------------------------------------------------------------------------------------- storage
def test_storage_events_alerts_roundtrip():
    st = Storage(":memory:")
    e = Event(at(1), "synthetic", "process_start", "h", "k1", 1, None, None, r"C:\a.exe")
    sid = st.start_scan("test", "h")
    assert st.save_events([e, e], sid) == 2  # duplicates ignored by primary key
    assert st.counts()["events"] == 1
    got = st.load_events(kind="process_start")[0]
    assert got.proc_key == "k1" and got.ts == e.ts and got.image == e.image
    a = Alert("A-1", "SHIELD-001", "t", "low", at(2), "h", "obs", "s", conditions_met=["c"], mitre=[{"id": "T1547.001", "name": "n"}])
    st.save_alerts([a], sid)
    r = st.load_alerts(severity="low")[0]
    assert r.alert_id == "A-1" and r.mitre[0]["id"] == "T1547.001" and st.load_alerts(severity="high") == []
    assert st.load_alerts(rule_id="SHIELD-001") and not st.load_alerts(rule_id="SHIELD-002")


def test_baseline_overwrite_protection():
    st = Storage(":memory:")
    files = [{"relpath": "a.txt", "sha256": "ab" * 32, "size": 1, "mtime": 1.0, "mode": 420}]
    st.save_baseline("/r", files, host="h", skipped=0, options={})
    with pytest.raises(BaselineExists):
        st.save_baseline("/r", files, host="h", skipped=0, options={})
    st.save_baseline("/r", [], host="h", skipped=0, options={}, overwrite=True)
    loaded, meta = st.load_baseline("/r")
    assert loaded == {} and meta["file_count"] == 0 and st.load_baseline("/other") is None


def test_persistence_baseline_roundtrip_and_latest():
    st = Storage(":memory:")
    assert st.load_persistence_baseline("h") is None
    st.save_persistence({"entries": {"a": 1}}, host="h", platform="windows", baseline=True)
    st.save_persistence({"entries": {"a": 1, "b": 2}}, host="h", platform="windows", baseline=True)
    st.save_persistence({"entries": {}}, host="h", platform="windows", baseline=False)  # not a baseline
    assert st.load_persistence_baseline("h")["entries"] == {"a": 1, "b": 2}


def test_prune_and_clear_and_export():
    st = Storage(":memory:")
    old = Event(parse_ts("2020-01-01T00:00:00Z"), "s", "process_start", "h", "old", 1, None, None, "a.exe")
    new = [Event(at(i), "s", "process_start", "h", f"k{i}", i, None, None, "a.exe") for i in range(5)]
    st.save_events([old] + new)
    assert st.prune(max_events=3, max_days=3650 * 20)["events_deleted"] == 3  # 6 events -> keep newest 3
    st.save_events([old])
    assert st.prune(max_events=100, max_days=30)["events_deleted"] >= 1  # age-based
    st.save_baseline("/r", [], host="h", skipped=0, options={})
    st.save_alerts([Alert("A-1", "R", "t", "low", at(1), "h", "o", "s")])
    ex = st.export()
    assert ex["counts"]["alerts"] == 1 and ex["alerts"][0]["alert_id"] == "A-1"
    st.clear()
    assert st.counts()["events"] == 0 and st.counts()["alerts"] == 0 and st.has_baseline("/r")  # baselines survive by default
    st.clear(include_baselines=True)
    assert not st.has_baseline("/r")


def test_transaction_rollback_keeps_db_consistent():
    st = Storage(":memory:")
    with pytest.raises(RuntimeError):
        with st.tx() as c:
            c.execute("INSERT INTO scans(ts, command) VALUES ('t','x')")
            raise RuntimeError("boom")
    assert st.counts()["scans"] == 0


def test_indexes_exist_and_file_db_persists(tmp_path):
    p = tmp_path / "d" / "x.db"
    st = Storage(p)
    names = {r[0] for r in st.conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert {"idx_events_ts", "idx_events_kind", "idx_alerts_ts", "idx_alerts_rule"} <= names
    st.save_alerts([Alert("A-1", "R", "t", "low", at(1), "h", "o", "s")])
    st.close()
    assert Storage(p).counts()["alerts"] == 1


def test_database_newer_schema_is_refused(tmp_path):
    p = tmp_path / "n.db"
    c = sqlite3.connect(p)
    c.execute("PRAGMA user_version=99")
    c.close()
    from spyshield.core.storage import StorageError
    with pytest.raises(StorageError):
        Storage(p)


def test_symlink_branch_without_needing_symlink_privileges(tmp_path, monkeypatch):
    """Windows non-admin often cannot create symlinks, so exercise the symlink branch with a stand-in DirEntry."""
    root = mkdir_files(tmp_path, {"a.txt": "a"})
    real_scandir = os.scandir

    class LinkEntry:
        name, path = "lnk", str(tmp_path / "lnk")

        def is_symlink(self):
            return True

        def stat(self, follow_symlinks=True):
            assert follow_symlinks is False  # must never follow
            return os.stat(str(tmp_path / "a.txt"))

        def is_dir(self, follow_symlinks=True):
            raise AssertionError("a symlink must not be traversed")

    def fake(path):
        return list(real_scandir(path)) + ([LinkEntry()] if str(path) == root else [])
    monkeypatch.setattr(os, "scandir", fake)
    files, st = filesystem.scan_directory(root)
    assert files["lnk"]["is_symlink"] and files["lnk"]["sha256"] is None and st["symlinks"] == 1 and "a.txt" in files
