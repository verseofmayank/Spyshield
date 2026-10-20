# Detection rules

Defined in [`config/rules.yaml`](../config/rules.yaml); validated on load (`python spyshield.py rules`). Every alert is an
**observation requiring analyst review**. None of these rules says "malware". Severity reflects how much attention the
stated conditions deserve; confidence reflects how reliable that evidence is.

Shared lists (editable): `suspicious_path_patterns` (temp, `Windows\Temp`, `Users\Public`, `$Recycle.Bin`, `/tmp`, `/var/tmp`,
`/dev/shm`), `allowlist_image_patterns` (Program Files, System32, a Chocolatey temp path), `allowlist_process_names`.
`Downloads` and `AppData\Roaming` are deliberately **not** in the suspicious list because legitimate software uses them heavily.

| ID | Telemetry | Type | Severity | Confidence |
|---|---|---|---|---|
| SHIELD-001 | process, sysmon | exec_location | low (medium if parent is a document/script host) | low |
| SHIELD-002 | process, sysmon | parent_child | medium | low |
| SHIELD-003 | persistence | persistence_change | low (medium if target in a suspicious path) | medium |
| SHIELD-004 | process, network | proc_net_correlation | medium | medium |
| SHIELD-005 | fim | fim_change | low by default; per-path (e.g. hosts file, `.ssh` = high) | high (that it changed) |
| SHIELD-006 | network | outbound_rate | low | low |
| SHIELD-007 | sysmon | sysmon_chain | medium | medium |
| SHIELD-008 | persistence, process | persistence_exec | medium (high if path suspicious) | medium |
| SHIELD-009 | watchlist | ioc_match | medium | medium |

## SHIELD-001 Process executed from a user-writable temporary location (Rule A)
*Conditions:* image path matches a suspicious pattern, is not allowlisted, has an executable extension (`.exe .scr .com .bat .cmd .ps1 .vbs .js .jse .wsf .msi`). *Escalation:* parent in `escalate_if_parent_in` (Office, Acrobat, mshta, wscript, cscript) → medium; the alert lists which condition applied and says plainly when it was "location only".
*Evidence:* process_start (path, parent, command line redacted). *False positives:* installers, updaters, portable apps, build output. *Not triggered by:* ordinary apps outside Program Files, files with non-executable extensions, allowlisted paths.

## SHIELD-002 Unusual parent-child relationship (Rule B)
*Conditions:* configured `pairs` (parent list × child list, case-insensitive basename), e.g. WINWORD/EXCEL/POWERPNT/OUTLOOK/AcroRd32 → powershell/cmd/wscript/cscript/mshta/rundll32/regsvr32; wmiprvse → powershell/cmd. Parent found by key or PPID with PID-reuse guard; alert shows the lineage chain. *False positives:* add-ins, macros, PDF helpers, IT scripts. Add your own pairs in YAML.

## SHIELD-003 New or modified startup entry (Rule C)
*Conditions:* persistence change `added`/`modified` (vs trusted baseline, or a Sysmon registry event on a Run/RunOnce key). Escalates when the referenced target is in a suspicious path. Includes location, entry name, command, target path, and file metadata (exists, size, SHA-256 if ≤ 50 MB). *MITRE:* **T1547.001** only for Windows Run/RunOnce/Startup-folder evidence; Linux autostart gets no mapping (that technique is a different one). *False positives:* every software install. The baseline must be taken on a trusted state.

## SHIELD-004 Recently started suspicious-location process with outbound connection (Rule D)
*Conditions:* process image in a suspicious location (not allowlisted) **and** an outbound connection to a *public* address by the same `proc_key` within `window_seconds` (300) of the process's **creation time**. Both observations are attached as evidence. Not triggered: connection after the window, private/loopback destinations (`public_only`), process with no recorded start, a different process that reused the PID.

## SHIELD-005 File integrity change (Rule E)
*Conditions:* `created`/`modified`/`deleted` against the stored baseline (or watch mode). Severity by `path_severity` patterns else `default_severity`. Modification basis is SHA-256, or size+mtime when the file was too large to hash (stated in the alert).

## SHIELD-006 High outbound connection activity (Rule F)
*Conditions:* for one `proc_key`, within `window_seconds` (60): distinct public destinations > `max_distinct_destinations` (25) or new connections > `max_new_connections` (60). Re-observations of the same socket by later polls are not counted; connections already open when monitoring began (`initial`) are ignored; private/loopback ignored; browsers by *path* (`ignore_image_patterns`) and `allowlist_process_names` ignored. Alert states count, window, process. **Never interpreted as C2 on its own.** This rule initially fired on a normal Chrome snapshot during development, which led to the `initial` and path-ignore logic.

## SHIELD-007 Suspicious Sysmon process chain (Rule G)
*Conditions:* a Sysmon network event (ID 3, outbound) and a Sysmon process creation (ID 1) with the **same ProcessGuid**, connection within `window_seconds` (300), matching an analyst-defined chain: `image_regex`, `parent_regex`, `require_suspicious_path`, `require_public_connection`. Default chains: Office → interpreter → public connection; suspicious-location executable → public connection. Only fires for Sysmon-sourced events.

## SHIELD-008 Startup entry plus execution (Rule H)
*Conditions:* persistence `added`/`modified` with a target path, and a process whose image path equals that target (normalised) starting **after** the entry within `window_seconds` (24 h). Works in either arrival order. High when the path is suspicious, else medium. Limitation: `.lnk` shortcuts in Startup folders cannot be resolved to their target without parsing the shortcut, so folder entries match only direct executables.

## SHIELD-009 Local IOC watchlist match
*Conditions:* exact match of SHA-256 (process or file event hash), remote IP, path glob, or image basename against `config/ioc.yaml`. The alert quotes the watchlist `source` and `updated` date and says it is a lead, not proof. SpyShield never downloads feeds.

## Tuning
Change thresholds/lists in YAML; run `python spyshield.py rules` to validate. Unknown fields or bad values fail at startup with every problem listed. Use `enabled: false` to disable a rule. Poll interval must be ≥ 0.5 s.
