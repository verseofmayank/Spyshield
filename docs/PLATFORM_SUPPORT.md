# Platform support

| Capability | Windows 10/11 | Linux | Notes |
|---|---|---|---|
| Process snapshot / tracking | **verified live** (Windows 11, Python 3.13) | test suite run on Ubuntu 24.04 (WSL), live psutil smoke test passes | Access-denied fields are reported as limited |
| Network connections → process | **verified live** | test suite run on Ubuntu 24.04 (WSL) | Needs privileges on Linux for other users' sockets |
| Persistence: Run/RunOnce (HKCU, HKLM, WOW6432Node) | **verified live (read-only)** | n/a | `winreg` with `KEY_READ` only |
| Persistence: Startup folders | **verified live** | n/a | `.lnk` targets are not resolved |
| Persistence: XDG autostart, systemd *user* units | n/a | partial; unit-tested with a temp home | No cron, no system services |
| File integrity (baseline/compare) | **verified live** | test suite run on Ubuntu 24.04 (WSL) | Pure Python, `os.scandir` |
| File watch (watchdog) | **verified live** (test creates/modifies files) | test suite run on Ubuntu 24.04 (WSL) | |
| Sysmon XML analysis (offline) | **verified** (platform-independent) | works on any OS | Fixtures are synthetic |
| Live Sysmon log read (`analyze --live-sysmon`) | **UNVERIFIED** (Sysmon not installed on the dev machine; error path tested with a mock) | not available | Uses documented `wevtutil qe`; needs Sysmon + permission |
| SQLite, reports, rules, demo | verified | supported | |
| macOS | persistence reported as unsupported | | not a target |

## Privileges
* **No administrator rights are required** for any command. Without them: ~half of processes on the dev machine have
  inaccessible fields (exe/user/cmdline), reported as "limited"; HKLM Run keys are readable by standard users; some
  connection↔PID links may be missing. SpyShield prints a note when not elevated and never escalates privileges.
* Reading the Sysmon operational log normally requires an elevated prompt or membership in *Event Log Readers*.

## Sysmon requirements
SpyShield **never installs or reconfigures Sysmon**. For the Sysmon rules, your own Sysmon configuration must enable at least
event IDs 1 (process create) and 3 (network connect); 11/13/22 add file, registry and DNS context. Events with other IDs are
counted as unsupported, events missing mandatory fields as malformed; neither is guessed. Offline export: `wevtutil qe
Microsoft-Windows-Sysmon/Operational /f:xml > events.xml` (run by you), then `spyshield analyze --events events.xml`.

## Steps to validate Windows-specific behaviour yourself
1. `python spyshield.py persistence --save-baseline` on a trusted state, later `persistence --diff`.
2. Create a harmless test entry: `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v SpyShieldTest /d "C:\Windows\System32\notepad.exe"`, run `persistence --diff` (expect SHIELD-003), then remove it with `reg delete ... /v SpyShieldTest /f`. (SpyShield will not do either of these for you.)
3. `python spyshield.py monitor --duration 30`, copy `C:\Windows\System32\ping.exe` to `%TEMP%\x\ping_copy.exe` and run `ping_copy.exe -n 10 127.0.0.1` (expect SHIELD-001).
4. With Sysmon installed: `python spyshield.py analyze --live-sysmon --count 200`.

## Unsupported / not implemented
Kernel-level telemetry (ETW, drivers), packet capture (see PacketForge), memory forensics, scheduled tasks and services
persistence, WMI subscriptions, cron/launchd inspection, per-event file attribution, process termination or any response action.
