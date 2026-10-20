# SpyShield: progress

Legend: [x] done and tested | [~] done with stated limits | [ ] not done

## P0 core
- [x] Audit (`docs/AUDIT.md`)
- [x] Modular package, normalised UTC event schema
- [x] Process monitoring (PID-reuse safe, redacted command lines, opt-in size-limited hashing)
- [x] Process-aware network monitoring + IP classification
- [x] File integrity monitoring: baseline, compare, watch mode, safeguards
- [x] Rule engine (YAML, validated) and rules SHIELD-001..009 with correlation windows
- [x] CLI (scan, processes, network, persistence, baseline, fim, monitor, analyze, alerts, report, demo, rules, data)
- [x] Offline demo with 14 labelled synthetic scenarios
- [x] Tests: 163 passed, 1 skipped (see docs/test-results.txt)

## P1
- [x] Windows persistence (Run/RunOnce, Startup folders; read-only; verified live on Windows 11)
- [x] Sysmon XML analysis (events 1, 3, 5, 11, 12, 13, 22) with ProcessGuid correlation
- [~] Live Sysmon log read: implemented via `wevtutil`, **UNVERIFIED** (Sysmon not installed on the dev machine)
- [x] Correlation, dedupe/cooldown, IOC watchlist, SQLite alert storage
- [x] JSON / CSV / standalone HTML reports

## P2 / pending
- [~] Linux support is partial (autostart + systemd user units); not run on Linux here; CI job configured but not run
- [ ] `.lnk` shortcut target resolution for Startup-folder entries
- [ ] Scheduled tasks / services / WMI persistence
- [ ] ETW-based telemetry; DNS-based correlation from Sysmon event 22
- [ ] Choose and add a LICENSE
