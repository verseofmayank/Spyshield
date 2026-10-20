# Testing

```bash
pip install -r requirements-dev.txt
python -m pytest
```
No administrator rights, internet, API keys or malware are needed. Tests use fakes for `psutil` objects, an in-memory fake
Registry, `tmp_path` directories, hand-written Sysmon XML and synthetic events. They never touch real startup locations.

**Recorded result** (Windows 11, Python 3.13.7, development machine; full verbose output in [test-results.txt](test-results.txt)):
```
======================= 163 passed, 1 skipped in 25.22s =======================
```
The one skip is `test_symlinks_are_not_followed_and_loops_are_safe`: Windows without Developer Mode/administrator refuses to create
symlinks, so the test skips itself. The same code path is exercised by `test_symlink_branch_without_needing_symlink_privileges`
(stand-in directory entry). The Linux CI job is configured in `.github/workflows/tests.yml` but **was not run locally (UNVERIFIED)**.

## What is covered
| File | Areas |
|---|---|
| `tests/test_collectors.py` | process metadata normalisation, access-denied, vanished process, redaction, process start/end tracking, **PID reuse**, parent-older-than-child guard, creation-time timestamps, hashing limits; IP classification, connection attribution, connection-table denial, initial flag, live psutil smoke test; Registry snapshot/diff (fake), startup folders, Linux autostart, platform/unsupported reporting, real read-only Registry read; FIM hashing, create/modify/delete, exclusions, size/count limits, symlinks (real and mocked), inaccessible dirs/files, root refusal, no file contents in events, real watchdog watch; rules/IOC config validation; SQLite round-trips, baseline overwrite protection, retention, export/clear, rollback, indexes, schema version |
| `tests/test_detection.py` | each rule matching **and** non-matching, thresholds at the boundary, window expiry, PID reuse, out-of-order input, name-only and port-only false positives, allowlists, escalation, IOC exact/near-miss, dedupe + cooldown, alert schema, bounded history, polling limitation text, disabled rules, Sysmon parsing (valid, malformed, unsupported, XXE rejection, oversize, out-of-order, live-read errors), labelled scenario evaluation |
| `tests/test_reports_cli.py` | HTML escaping of every field, offline/standalone HTML, required sections, JSON schema, CSV formula-injection safety, hostname anonymisation, CLI commands end to end (demo, analyze, alerts, report, baseline/fim/watch, persistence, scan/processes/network/monitor live, data export/clear), bad input handling, and **safety tests** (source contains no process-termination, Registry-write, keylogging/clipboard/camera/network-exfil APIs or self-persistence; Registry opened `KEY_READ` only) |

## Detection outcomes on labelled synthetic fixtures
`python spyshield.py demo` (also asserted by `test_all_labelled_scenarios_match_expectations`):

| Scenario | Label | Rules fired | Outcome |
|---|---|---|---|
| S01 normal processes | benign | none | TN |
| S02 normal connections incl. ports 5228/8443/8080, loopback, private | benign | none | TN |
| S03 executable from temp | should alert | SHIELD-001 | TP |
| S04 new Run entry (fake Registry) | should alert | SHIELD-003 | TP |
| S05 temp process + outbound connection | should alert | SHIELD-001, 004 | TP |
| S06 modified file (temp folder) | should alert | SHIELD-005 | TP |
| S07 unchanged baseline | benign | none | TN |
| S08 hash IOC match | should alert | SHIELD-009 | TP |
| S09 noisy app named "SpyGlass-Recorder" | benign | none | TN |
| S10 malformed Sysmon events | benign | none | TN |
| S11 Word → PowerShell | should alert | SHIELD-002 | TP |
| S12 startup entry then execution | should alert | SHIELD-001, 003, 008 | TP |
| S13 many destinations | should alert | SHIELD-006 | TP |
| S14 Sysmon Office → PowerShell → connect | should alert | SHIELD-002, 003, 007 | TP |

**TP 9, FN 0, TN 5, FP 0.** These fixtures were written together with the rules, so 100 % here shows the rules behave as
designed; it says nothing about detection rates on real attacks or on real, noisy hosts.

## Bugs found while testing
Live `scan` raised SHIELD-006 on normal Chrome (fixed: initial connections ignored, path-based ignore list); full process
snapshot took 6 s (fixed: one-shot PPID map, dropped slow fields → ~1 s) which had made the first live monitor test miss a
process; `Authorization: Bearer <token>` was only half-redacted (fixed: Bearer handled first); XML fragment splitting let one
broken Sysmon event swallow the next valid one (fixed: split at each `<Event`); test fakes collided with real PIDs in the PPID map.
