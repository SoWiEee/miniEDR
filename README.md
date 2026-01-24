# MiniEDR (Phase 2) — Sysmon + ETW → Rules + Correlation → Alerts

MiniEDR is a C++ Windows EDR starter project designed for learners who are new to Windows telemetry and detection engineering.

Phase 2 expands Phase 1 in two directions:

1) More telemetry coverage (Sysmon + an optional NT Kernel Logger ETW consumer)
2) More detection capability (data-driven JSON rules + a stateful correlator)

This is still an educational project. The goal is clarity and extensibility, not production completeness.

## What Phase 2 includes

Telemetry (user mode)

- Sysmon collector (Windows Event Log API: `EvtSubscribe` + `EvtRender`)
  - Normalizes selected Sysmon events:
    - EID 1  ProcessCreate
    - EID 3  NetworkConnect
    - EID 7  ImageLoad
    - EID 8  CreateRemoteThread
    - EID 10 ProcessAccess
    - EID 11 FileCreate
    - EID 13 Registry value set
    - EID 22 DNS query
    - EID 23/26 File delete (depends on Sysmon version)

- ETW collector (optional)
  - Consumes the **NT Kernel Logger** in real time for:
    - Process events (ProcessGuid) → mapped to `ProcessCreate`
    - Image load events (ImageLoadGuid) → mapped to `ImageLoad`
  - This is a minimal educational implementation. It uses EventTrace APIs (`StartTrace` / `OpenTrace` / `ProcessTrace`) and TDH property extraction.

Detection

- Data-driven JSON ruleset (`rules/default_rules.json`)
  - Simple condition model: `equals_any`, `contains_any`, `regex_any`
  - Field paths like `proc.image`, `proc.command_line`, `target.image`, `fields.GrantedAccess`, `type`
- Stateful correlation (Phase 2 correlator)
  - CORR-INJ-001: `ProcessAccess (high-rights)` followed by `CreateRemoteThread` within a short window

Output

- Console alerts
- JSONL alerts (`alerts.jsonl`) including:
  - Source (`sysmon` / `etw`), event id/opcode
  - Actor + Target process info (where available)
  - Up to a few event-specific fields

## What Phase 2 does NOT include (yet)

- Kernel driver (ObRegisterCallbacks, PsSetCreateProcessNotifyRoutineEx, etc.)
- Memory scanning (YARA), hooking, sandboxing, response actions
- Deep post-event scanners (pe-sieve / hollows_hunter adapters)
- Full XML parsing / strong schema validation (normalizer uses pragmatic string extraction)

Those are good Phase 3/4 targets.

## Build requirements

- Windows 10/11 x64
- Visual Studio 2022 with C++ workload
- CMake 3.21+
- Sysmon installed (Sysinternals)
- Administrator privileges recommended (Sysmon subscription and ETW kernel session typically require it)

The agent links against:
- `wevtapi.lib` (Windows Event Log)
- `advapi32.lib` and `tdh.lib` (ETW / TDH)

## Sysmon setup (Phase 2)

The Phase 2 Sysmon config is in:

- `tools/sysmon/sysmonconfig.xml`

Install / update (Administrator):

- `sysmon64.exe -accepteula -i tools\sysmon\sysmonconfig.xml`
- `sysmon64.exe -c tools\sysmon\sysmonconfig.xml`

This config is intentionally permissive for learning; expect noise. In real environments you should tune filters and add excludes.

## Rules

Default rules live here:

- `rules/default_rules.json`

The agent attempts to load rules in this order:

1) `<exe_dir>\rules\default_rules.json`
2) `.\rules\default_rules.json`
3) `.\default_rules.json`
4) Built-in fallback rules (if none found)

You can edit the JSON rules without rebuilding.

## Build (CMake)

From a Developer PowerShell for VS:

- `cmake -S . -B build -G "Visual Studio 17 2022" -A x64`
- `cmake --build build --config Release`

Binary output:
- `build\bin\Release\miniedr.exe`

## Run

Recommended (Administrator):

- `build\bin\Release\miniedr.exe`

Optional flags:

- `--no-sysmon`  Disable Sysmon collector
- `--no-etw`     Disable ETW kernel collector

Outputs:
- Console alerts
- `alerts.jsonl` in the current working directory

## Repository layout

- `agent/` user-mode agent code
  - `collectors/` Sysmon + ETW collectors
  - `pipeline/` canonical event schema + normalizer
  - `detection/` rule engine + correlator
  - `output/` alert sinks
  - `utils/` small utilities (encoding, JSON parser, path helpers)
- `tools/sysmon/` Sysmon configuration
- `rules/` default JSON ruleset

## Roadmap (suggested)

- Phase 3: adapters for pe-sieve / hollows_hunter, YARA memory scanning, signature/enrichment (hash reputation, signer info)
- Phase 4: response actions (kill process, isolate host, block network), optional kernel driver telemetry

## Safety and ethics

This project is for defensive research and education. Test only in environments you own or are authorized to assess.


## Phase 3: On-demand deep scans (pe-sieve / hollows_hunter)

Phase 3 adds optional, on-demand deep scanning for **already-alerted** PIDs. This is the core performance idea:
MiniEDR only pays the cost of memory scanning when detection rules/correlation have already raised suspicion.

Trigger logic (configurable):
- Severity is **High** or **Critical**, or
- `rule_id` contains a substring listed in `agent/config/scanners.json` → `scan_rule_ids`

Adapters included:
- **PE-sieve** (single PID scan via `/pid`)
- **HollowsHunter** (PID-targeted scan via `/pid` plus `/dir` + `/uniqd`)

Outputs:
- Each scan creates a unique folder under `scan_outputs/` by default.
- MiniEDR reads JSON reports (when present) and marks a scan `suspicious=true` using a lightweight heuristic:
  `modified.total > 0` (from the report).

### Setup

1) Download the latest releases of PE-sieve and/or HollowsHunter and put the executables into `tools/bin/`:
- `tools\bin\pe-sieve64.exe`
- `tools\bin\hollows_hunter64.exe`

2) Verify configuration:
- `agent\config\scanners.json`

3) Run MiniEDR (Administrator recommended). When a scan triggers, console output shows an "On-demand scans" block
and `alerts.jsonl` includes a `scans` array.

See also: `docs/scanners.md`.
