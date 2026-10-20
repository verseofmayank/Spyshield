# SpyShield: audit of the original implementation

Audited commit `685d380`. Files read: `main.py` (120 lines), `README.md`, `requirements.txt` (`psutil`),
`detection_sample.log`, `.gitignore`, and the Git history (6 commits). The whole program is one script with a
process-name keyword scan and a "non-80/443 port" network scan, each followed by an interactive kill prompt.

| # | Concern from the brief | Verified? | Evidence |
|---|---|---|---|
| 1 | Process detection relies on name keywords | **Confirmed** | `detect_suspicious_processes`: `any(k in name for k in ['keylogger','logkeys','xinput','hook','capture','spy','record'])`. Nothing else is examined (no path, parent, command line, hash, network). |
| 2 | Names like `capture`/`record`/`spy`/`hook` can be legitimate | **Confirmed** | Substring match: `screencapture`, `SoundRecorder`, `GameBarPresenceWriter`-style names, `xinput1_3`/input utilities, anything containing `hook` all match. A malicious process simply uses another name. |
| 3 | Non-80/443 ports treated as suspicious | **Confirmed** | `if remote_port not in [80, 443]`. On the audit machine **21 of 63** ESTABLISHED connections matched this rule, including loopback traffic. The committed `detection_sample.log` is almost entirely `WUDFHost.exe`/`ipfsvc.exe` to `127.0.0.1` and Chrome (QUIC/FCM-style ports): all benign, all flagged. |
| 4 | Prompts to terminate without sufficient evidence | **Confirmed** | `input("Do you want to terminate ...")` after every hit, then `terminate()` then `kill()`. Wrong kills of user software are likely, and terminating a keylogger does not remove persistence. |
| 5 | Protected-process list is incomplete/unreliable | **Confirmed** | 12 hard-coded names compared by **name only**: a malicious `svchost.exe` in `%TEMP%` would be "protected", while real critical processes not listed (`System`, `Registry`, `MsMpEng.exe`, `csrss` variants, `lsm`, Linux `systemd`, `init`) are not. Name equality is not identity. The list also contains `WUDFHost.exe` and `ipfsvc.exe`, suggesting it was grown to silence noise rather than designed. |
| 6 | Processes and connections not meaningfully correlated | **Confirmed** | The network scan looks up only the process *name*; no path, parent, start time or earlier process observation is considered. |
| 7 | No persistent state or normalised events | **Confirmed** | Output is `print` plus a free-text `detection.log`. No event schema, no history, no UTC timestamps (local time via `logging`), no baseline. |
| 8 | No rule engine | **Confirmed** | Detection logic and thresholds are hard-coded in two functions. |
| 9 | No automated tests | **Confirmed** | No `tests/`. |
| 10 | Findings are not verified malware/keylogger detection | **Confirmed** | README says it "detects keyloggers" and "terminates malicious processes". A keyword in a process name is not evidence of a keylogger. User-mode polling cannot see keyboard hooks installed via `SetWindowsHookEx` anyway. |

## Additional defects
* **PID reuse not handled.** Alerts and kill decisions are keyed by bare PID; between detection and the `y/n` answer the PID may belong to another process.
* **`conn.raddr` handling:** `remote_port = "Unknown"` is compared to `[80, 443]`, so listening/half-open entries can be flagged.
* **IPv6/loopback not classified**; no allowlisting; the same connection is re-reported on every scan.
* **Command lines / paths** are not collected, so secrets-in-argv redaction was never needed; the new design collects command lines, so redaction is added.
* **README claims** (keylogger detection, termination of malicious processes) are not supported by the code.
* **Logging:** `logging.basicConfig` at import time; log file written to the CWD; unicode arrows in the committed sample log were mis-encoded (`→`).
* **Dependencies unpinned**, Python version unspecified ("3.x").
* `main.py` blocks on `input()` so it cannot run unattended or be tested.

## What was worth keeping
* The use of `psutil` and the read-only enumeration idea.
* Graceful handling of `NoSuchProcess` / `AccessDenied` / `ZombieProcess`.
* The "educational / authorised use only" disclaimer.

## Resolution summary
| Original behaviour | Replacement |
|---|---|
| keyword name match | removed as a detection method; names are context only (rules use path, ancestry, correlation, IOC exact match) |
| non-80/443 flagged | removed; rate/destination thresholds with allowlists and public-only filtering |
| terminate prompt | **removed entirely**; SpyShield never terminates anything |
| `CRITICAL_PROCESSES` | removed (nothing is killed, so there is nothing to protect) |
| free-text log | normalised UTC events + SQLite + JSON/CSV/HTML reports |
| `main.py` | replaced by `spyshield.py` + package (history preserved in Git) |
