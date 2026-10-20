# SpyShield architecture

```
spyshield.py                 entry point
spyshield/
  cli.py                     Click commands, Rich output, clean error handling
  demo.py                    synthetic labelled scenarios + evaluation
  core/   models.py          Event, Alert (normalised schema, UTC timestamps)
          config.py          rules.yaml / ioc.yaml loading and validation
          storage.py         SQLite investigation database
          redact.py          command-line / secret redaction
          pathutil.py        path normalisation, glob matching, target extraction
  collectors/ processes.py   psutil process snapshots + lifecycle tracker
              network.py     psutil connections + address classification
              persistence.py Run/RunOnce + Startup folders (read-only), Linux autostart
              filesystem.py  FIM baseline/compare/watch
              sysmon.py      Sysmon XML parsing/normalisation (+ optional live read)
  detection/ engine.py       ingestion, rule dispatch, dedupe/cooldown
             rules.py        rule evaluators (logic)
             correlation.py  bounded history, lineage, lookups
  reporting/ export.py       JSON / CSV / HTML builders;  terminal.py  Rich tables;  report.html.j2
config/rules.yaml  config/ioc.yaml   samples/   tests/   docs/
```

## Pipeline
```
 collectors ──► Event (normalised) ──► Engine.process_batch (sort by time)
                                          │  History (bounded): processes by key, connections by process, persistence
                                          │  rules (YAML-configured) -> RuleHit -> Alert (dedupe + cooldown)
                                          ▼
                       SQLite (events, alerts, baselines, snapshots)  ──►  alerts / report (JSON, CSV, HTML)
```
Nothing in the pipeline writes to the monitored system. The only writes are to SpyShield's own SQLite file and report files.

## Event schema (`core/models.py`)
`ts` (aware UTC), `source` (psutil | sysmon | fim | persistence | synthetic), `kind` (process_start, process_end,
network_connection, file_change, persistence_change, registry_change, dns_query), `host`, `proc_key`, `pid`, `ppid`,
`parent_key`, `image`, `name`, `parent_image`, `cmdline` (redacted), `user`, `sha256`, `data` (kind-specific: remote_ip,
remote_port, remote_class, change, path, location, target_path, ...), `event_id` (deterministic hash), `seq`.

**Process identity (`proc_key`):** Sysmon `ProcessGuid` when available, else `"<pid>:<create-time>"`. PIDs are reused by
the OS, so a bare PID is never used to link events. A process's event timestamp is its **creation time**, not when it was
first observed, which is what makes "started N seconds before the connection" meaningful for polled data.

## Alert schema
`alert_id`, `rule_id`, `title`, `severity` (info/low/medium/high), `ts`, `host`, `observation`, `process`, `evidence`
(brief copies of the contributing events), `conditions_met` (explicit list), `confidence` + `limitations`, `mitre`
(only when justified), `false_positives`, `investigation_steps`, `status` ("requires analyst review"), `suppressed_count`.
Alerts are built only from events that exist; there is no code path that creates an alert without evidence.

## Correlation (`detection/correlation.py`)
* **Lineage:** parent found by explicit parent key; otherwise by PPID choosing the newest process with that PID that
  existed before the child (PID-reuse guard). Cycle-safe, depth-limited.
* **Process ↔ network:** connections indexed per `proc_key`; rule checks creation-to-connection time window.
* **Persistence ↔ execution:** persistence events kept in a bounded deque; matched to process starts by normalised path
  in either arrival order, requiring execution *after* the entry within the window.
* **Sysmon:** same logic, keyed by ProcessGuid.
* **Out-of-order input:** `process_batch` sorts by `(ts, arrival)` before evaluation (offline exports are often unordered).
* **Bounds:** at most `max_history_events` processes retained (oldest dropped), 500 connections per process, bounded
  persistence history, bounded rate-rule state.
* **Dedupe/cooldown:** identical `(rule, subject)` inside `cooldown_seconds` (event time) increments `suppressed_count`
  instead of producing a new alert.

## Rule engine
Rules are YAML (`config/rules.yaml`), validated at startup (types, severities, telemetry names, MITRE id format, numeric
thresholds, regex validity, unique ids, setting types, minimum poll interval). Each rule `type` maps to a Python evaluator
in `detection/rules.py`; there is no custom expression language. See [DETECTION_RULES.md](DETECTION_RULES.md).

## Storage (`core/storage.py`)
SQLite, WAL, explicit transactions (`BEGIN/COMMIT/ROLLBACK`), schema version via `PRAGMA user_version` (newer schema is
refused), indexes on event time/kind/process and alert time/rule/severity, retention pruning by count and age,
`export` (JSON), `clear` (needs `--yes`; baselines kept unless asked). FIM baselines are keyed by directory and
**cannot be overwritten without `--force`**. Stored: normalised events (command lines already redacted), alerts, file
hashes/metadata, startup entries. Not stored: file contents, passwords, keystrokes, clipboard.

## Reporting
HTML: Jinja2 with autoescape for every value, strict CSP meta tag, inline CSS, no JavaScript, no external resources, works
offline. CSV: leading `= + - @` in cells is neutralised (spreadsheet formula injection). Hostnames are replaced by a short
hash unless `--show-hostname`. Terminal output escapes untrusted text before Rich markup is applied.

## Performance choices
Bounded polling (≥ 0.5 s), `process_iter` snapshot ≈ 1 s for ~350 processes on the dev machine after two optimisations found by
profiling: a one-shot PPID map (psutil's per-process `ppid()` rebuilds it on Windows) and skipping `status()`/`cpu_percent()`.
Hashing is opt-in and size-limited (50 MB default) and cached per image path.

## Design decisions
* **No automatic response.** Detection and response are separated; response needs a human (and killing a process does not remove persistence).
* **Polling plus optional Sysmon** rather than kernel drivers/ETW: portable and unprivileged, with known blind spots (documented).
* **Rules over scores.** Severity/confidence are stated per rule with explicit conditions; no opaque risk number.
* **SQLite over a server** for a single-host tool; **YAML** for analyst-editable rules without a custom DSL.
* **Standard library where enough:** `winreg`, `sqlite3`, `xml.etree` (with DOCTYPE/ENTITY input rejected), `ipaddress`.
  Dependencies: psutil, watchdog, PyYAML, rich, click, Jinja2. `pywin32` was not needed.
