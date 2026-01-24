# MiniEDR (Phase 1) — Sysmon → Rules → Alerts

MiniEDR is a C++ Windows EDR starter project. This Phase 1 milestone focuses on one end-to-end path:

1. Collect telemetry from Sysmon (Windows Event Log, channel: `Microsoft-Windows-Sysmon/Operational`)
2. Normalize events into a small canonical schema (Phase 1 keeps the raw XML as evidence)
3. Evaluate baseline rules on ProcessCreate (Sysmon Event ID 1)
4. Emit alerts to console and to `alerts.jsonl`

This phase is intentionally minimal so new Windows security learners can read the code without getting buried in frameworks.

## What Phase 1 includes

- Sysmon collector via Windows Event Log API (`EvtSubscribe` + `EvtRender`)
- Normalizer for Sysmon EID 1 extracting:
  - Image, CommandLine, ProcessId, ParentProcessId, User, TimeCreated
- Simple in-process rule engine (hardcoded rules for approachability)
- Alert sinks:
  - Console output
  - JSON Lines file (`alerts.jsonl`) appended in the working directory

## What Phase 1 does NOT include (yet)

- ETW, kernel driver callbacks, on-demand scanners (pe-sieve / hollows_hunter), YARA memory scan
- Parent/child relationship enrichment (parent image) beyond what Sysmon XML provides directly
- Rule loading from YAML/JSON (planned in Phase 2)
- Automated response actions (planned later)

## Build requirements

- Windows 10/11 x64
- Visual Studio 2022 with C++ workload
- CMake 3.21+
- Sysmon installed and configured (Administrator required to subscribe reliably)

The project links against `wevtapi.lib`.

## Sysmon setup (minimal)

1. Install Sysmon (Sysinternals).
2. Apply the provided minimal config:

   - `tools/sysmon/sysmonconfig.xml` (enables ProcessCreate)

Example (run as Administrator):

- `sysmon64.exe -accepteula -i tools\sysmon\sysmonconfig.xml`

## Build (CMake)

From a Developer PowerShell for VS:

- `cmake -S . -B build -G "Visual Studio 17 2022" -A x64`
- `cmake --build build --config Release`

Binary output:
- `build\bin\Release\miniedr.exe`

## Run

Run as Administrator (recommended in Phase 1):

- `build\bin\Release\miniedr.exe`

You should see:
- Console alerts when rules match
- `alerts.jsonl` created/appended in the current working directory

## Phase 1 rules (baseline)

Rules are intentionally conservative triage signals:
- Office spawns script interpreter (PowerShell, cmd, wscript, mshta)
- Browser spawns PowerShell
- PowerShell with `-enc` / `-EncodedCommand`

You can review/edit them in:
- `agent/src/detection/rule_engine.cpp`

## Repository layout

- `agent/` user-mode agent code
- `tools/sysmon/` minimal Sysmon config
- `docs/` (reserved) architecture and rules documentation (Phase 2+)

## Roadmap

- Phase 2: ETW collector + correlation + move rules to a data-driven ruleset (YAML/JSON)
- Phase 3: on-demand deep scan adapters (YARA, pe-sieve, hollows_hunter)
- Phase 4: response actions + optional kernel driver telemetry/controls

## Safety and ethics

This project is for defensive research and education. Test only in environments you own or are authorized to assess.
