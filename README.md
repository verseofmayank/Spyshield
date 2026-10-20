# SpyShield: Host-Based Intrusion Detection & Endpoint Monitoring
**Author:** Mayank Kumar Karn

SpyShield is a **defensive, read-only** command-line HIDS for Windows (primary) and Linux (partial). It collects
process, network, startup-persistence and file-integrity telemetry (and analyses exported Sysmon events), normalises it
into one event schema, runs configurable, explainable detection rules with time-window correlation, stores everything in a
local SQLite database and produces SOC-style JSON / CSV / HTML reports.

**What it is not:** it is not antivirus, not EDR, not a keylogger detector, and not a remover of anything. Alerts are
**observations that need analyst review**, never verdicts of malware. SpyShield never terminates processes, edits the
Registry, creates its own persistence or sends telemetry anywhere.

> For use on systems you own or are authorised to monitor. See [Responsible use](#responsible-use).

## Why a rewrite
The original script flagged any process whose *name* contained words like `spy`, `capture` or `record`, flagged any
connection on a port other than 80/443 (21 of 63 ordinary connections on the audit machine), and asked to kill the process.
Those heuristics produce false positives and offer no evidence. Details: [docs/AUDIT.md](docs/AUDIT.md).

## Features (all implemented and tested; see [PROGRESS.md](PROGRESS.md))
| Area | What it does |
|---|---|
| Processes | PID, PPID, name, image path, creation time, user, CPU time, memory, redacted command line, opt-in size-limited SHA-256; start/exit tracking keyed by **(PID, creation time)** so PID reuse is handled; access-denied handled |
| Network | `psutil` connections attributed to processes; addresses classified public/private/loopback/reserved; time-windowed rules; **no packet capture** |
| Persistence | Read-only Run/RunOnce (HKCU/HKLM/WOW6432Node) and Startup folders; baseline + added/removed/modified diff. Linux: XDG autostart + systemd user units |
| File integrity | Explicit directories only; SHA-256 + metadata baseline; created/modified/deleted; `watchdog` real-time watch; symlinks never followed; size/count limits; contents never stored; baseline overwrite protection |
| Sysmon | Offline XML analysis (events 1, 3, 5, 11, 12, 13, 22) normalised, correlated by ProcessGuid; malformed/unsupported events counted; optional live read via `wevtutil` (**UNVERIFIED**, see platform doc) |
| Rules | 9 YAML rules (SHIELD-001..009), validated at load; every rule lists conditions, thresholds, severity, MITRE (only where justified), false positives, analyst steps |
| Correlation | process lineage, process<->network, persistence<->execution, Sysmon chains; bounded history; out-of-order offline events sorted; dedupe + cooldown |
| IOC watchlist | local file: SHA-256, IP, path, image name; exact matches only, labelled "investigation lead" |
| Storage | SQLite (WAL, transactions, indexes, retention, export, safe clear) |
| Reports | JSON, CSV (formula-injection safe), standalone offline HTML (autoescaped, no JS/CDN) |

## Install
```bash
git clone https://github.com/verseofmayank/Spyshield.git
cd Spyshield
python -m venv .venv
.venv\Scripts\activate            # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt   # Python 3.12+
python spyshield.py --help
```
Optional: `pip install -e .` provides a `spyshield` command. Development: `pip install -r requirements-dev.txt`.

## Commands
```bash
python spyshield.py demo                                      # offline, synthetic labelled scenarios + reports
python spyshield.py scan                                      # one read-only snapshot -> alerts
python spyshield.py processes --limit 20 [--hash]
python spyshield.py network
python spyshield.py persistence [--save-baseline] [--diff]
python spyshield.py baseline --path ./samples/monitored       # FIM baseline (explicit directory)
python spyshield.py fim --path ./samples/monitored [--watch 30]
python spyshield.py monitor --duration 60 [--interval 2] [--watch-path DIR]
python spyshield.py analyze --events samples/sysmon_events.xml
python spyshield.py alerts [--severity medium] [--rule SHIELD-004] [-d]
python spyshield.py report --format html|json|csv|all
python spyshield.py rules                                     # list/validate rules + watchlist
python spyshield.py data export -o all.json | data clear --yes | data prune
```
Global options: `--db FILE` (default `./spyshield-data/spyshield.db`), `--rules FILE`, `--ioc FILE`, `-v`.

## Real output (this machine, Windows 11, run during development)
Analysing the bundled synthetic Sysmon export (`analyze --events samples/sysmon_events.xml`):
```
Sysmon parse: 8 normalized, 1 malformed, 1 unsupported of 10; event IDs seen: {1: 3, 3: 1, 5: 1, 7: 1, 11: 1, 13: 1, 22: 1}
  skipped: event #9: process create needs ProcessGuid, ProcessId and Image
MEDIUM  SHIELD-002  'winword.exe' launched 'powershell.exe' (configured unusual parent-child pair)
MEDIUM  SHIELD-007  Sysmon chain 'Interpreter launched by an office application that then connects out': winword.exe -> powershell.exe -> 104.20.30.50:443
MEDIUM  SHIELD-003  Startup entry 'DemoUpdater' modified at sysmon-registry: "C:\Users\Public\runner_sim.exe"
```
A live `scan` of the development machine: 347 processes (164 with limited access without admin), 109 established connections
(all attributed), 22 startup entries, **0 alerts**: ordinary Chrome traffic on port 443/5228/other ports raised nothing.
A live `monitor` run during which a harmless copy of `ping.exe` was launched from a temp folder produced:
```
LOW  SHIELD-001  Process 'ping_copy.exe' started from a configured temporary/user-writable location: C:\Users\...\Temp\spyshield_live_demo\ping_copy.exe
```
The offline demo evaluates 14 labelled synthetic scenarios: **TP 9, FN 0, TN 5, FP 0**. That is a regression check on
hand-written fixtures designed with the rules, **not a production detection rate**. Generated demo reports are in
[examples/demo-output/](examples/demo-output/) (HTML/JSON/CSV, labelled SYNTHETIC).

## Limitations (read these)
* Polling (`psutil`) misses processes/connections shorter than the poll interval; Sysmon covers that better.
* Without administrator rights, some process fields and connection-to-PID links are unavailable (reported, not guessed).
* SpyShield cannot reliably detect keyloggers: user-mode polling cannot see keyboard hooks, and names/ports prove nothing.
* File integrity shows *that* a file changed, not who changed it or why.
* Rules are heuristics with listed false positives; thresholds need tuning per environment.
* Linux support is partial. Live Sysmon reading is UNVERIFIED (Sysmon not installed here). See [docs/PLATFORM_SUPPORT.md](docs/PLATFORM_SUPPORT.md).
* The test suite also passes on Linux (Ubuntu 24.04 under WSL, Python 3.12.3): 163 passed, 1 skipped. Live Linux collection beyond the tests (autostart/systemd on a real desktop) was not exercised.

## Responsible use
Run SpyShield only on systems you own or are explicitly authorised to monitor. It collects process command lines
(secrets redacted before storage) and file hashes (never contents) locally. Treat the database and reports as sensitive
and delete them with `data clear --yes` when no longer needed. It is not designed to monitor other people covertly: it runs
only when you start it, in the foreground, and prints what it does.

## Documentation
[ARCHITECTURE](docs/ARCHITECTURE.md) · [DETECTION_RULES](docs/DETECTION_RULES.md) · [PLATFORM_SUPPORT](docs/PLATFORM_SUPPORT.md) · [TESTING](docs/TESTING.md) · [AUDIT](docs/AUDIT.md) · [PROGRESS](PROGRESS.md)

## License
No license file is included yet; the author should choose one before others reuse the code.
