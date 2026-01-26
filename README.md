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


## Phase 3 (enhanced): Defense-in-depth add-ons

This update focuses on making the Phase 3 feature-set more complete, while keeping the project approachable.

### Deep post-event scanners (on-demand)

MiniEDR runs deep scanners **only after an alert** is generated (performance-first design). Adapters included:
- PE-sieve adapter (per-PID scan, reads `scan_report.json` when available)
- HollowsHunter adapter (per-PID scan, searches for JSON reports recursively)
- YARA adapter (runs `yara` CLI to scan a PID on-demand; bring your own rules)

Configuration:
- `agent/config/scanners.json` controls:
  - which severities/rule IDs trigger scans
  - tool paths (not redistributed): `tools\bin\pe-sieve64.exe`, `tools\bin\hollows_hunter64.exe`, `tools\bin\yara64.exe`
  - YARA rules folder (default: `rules\yara\`)

Operational note: YARA supports scanning a running process by using PID as the TARGET argument in the CLI. citeturn0search1turn0search9turn0search19

### Full XML parsing and stronger normalization

Sysmon events are rendered as XML via Windows Event Log APIs. Earlier phases used pragmatic string/regex extraction.
Phase 3 now prefers **XmlLite (IXmlReader)** parsing to extract:
- `EventID`
- `TimeCreated/@SystemTime`
- all `<Data Name="...">...</Data>` fields

This reduces parser fragility and is a stepping stone toward stronger schema validation. citeturn0search2turn0search10

### Response actions (optional; disabled by default)

A response manager scaffold is added (currently off by default) to keep the core detection path safe and predictable.
Implemented example action:
- terminate process for **Critical** alerts (when enabled)

Files:
- `agent/src/response/*`

You can extend this with: suspend process, isolate host/network, quarantine file, block hash, etc.

### Hooking and sandboxing (documented boundaries)

Hooking and sandboxing are complex and can be risky if enabled by default. In Phase 3 we:
- define intended module boundaries
- keep them opt-in / future work

See:
- `agent/src/hooking/README.md`
- `agent/src/sandbox/README.md`

### Kernel driver scaffolding (optional; not built in CMake)

Kernel callbacks (ObRegisterCallbacks, PsSetCreateProcessNotifyRoutineEx, etc.) are best implemented in a driver and require WDK.
Phase 3 adds a documentation scaffold under `driver/` with guidance and references to official samples. citeturn0search7turn0search3


## Phase 4: KMDF kernel driver telemetry (IOCTL)

Phase 4 adds a real **WDK/KMDF** kernel driver project that streams kernel telemetry events to user-mode via **IOCTL**.
This integrates with the existing architecture by introducing an additional collector (`DriverCollector`) that feeds
kernel events into the same Normalize/Rules/Correlator pipeline.

### What the driver provides (MVP)

The driver (`driver/MiniEDRDrv`) registers callbacks:
- Process create/exit: `PsSetCreateProcessNotifyRoutineEx`
- Image load: `PsSetLoadImageNotifyRoutine`
- Process handle audit: `ObRegisterCallbacks` (audit-only; no blocking in this milestone)

The driver stores events in a fixed-size nonpaged ring buffer and user-mode pulls events using:
- `DeviceIoControl(IOCTL_MINIEDR_GET_EVENTS)` on `\\.\MiniEDRDrv`

Shared IOCTL definitions:
- `driver/include/miniedr_ioctl.h`

### Build the driver

Prerequisites:
- Visual Studio 2022
- Windows Driver Kit (WDK) for Windows 10/11
- A test environment (VM recommended)

Open and build:
- `driver/MiniEDRDrv/MiniEDRDrv.vcxproj` (x64 Debug/Release)

### Install and run

The repo ships a minimal `MiniEDRDrv.inf` for test setups. Driver signing is enforced on modern Windows;
use appropriate developer/test signing methods in a VM. Do not deploy unsigned test drivers on production systems.

Once installed and started, the MiniEDR user-mode agent will automatically attempt to connect to `\\.\MiniEDRDrv`.
If the driver is unavailable, the agent continues without kernel telemetry (fail-open).

### Extending beyond MVP

Recommended next increments:
- Convert QPC timestamps to wall time in user-mode for consistent timelines
- Add optional enforcement policy (deny suspicious handle opens) with careful allowlists
- Add per-event variable payloads and schema versioning
- Add an IOCTL to request driver-side enrichments (e.g., image path from kernel cache)


### Phase 4+: Kernel telemetry enrichment (user-mode)

Kernel events are intentionally compact. After receiving a kernel event, the agent performs **best-effort enrichment**:
- Full image path (`QueryFullProcessImageName`)
- Command line (PEB read via `NtQueryInformationProcess` + `ReadProcessMemory`)
- User (`OpenProcessToken` + `LookupAccountSid`)
- Image hash (SHA-256)
- Authenticode signature verification and signer subject/issuer (best-effort)

These fields are stored into `CanonicalEvent.proc` / `CanonicalEvent.target` (`ProcessInfo`) for correlation and triage.
See: `agent/src/enrich/process_enricher.*`.


### Phase 4+: Optional enforcement policy (deny process access)

The KMDF driver can optionally **deny dangerous process-handle operations** against protected PIDs.
This is implemented in the `ObRegisterCallbacks` pre-operation callback.

How it works:
- The user-mode agent pushes a policy to the driver at startup (`agent/config/driver_policy.json`).
- The agent automatically adds its own PID to `protected_pids` and `allowed_pids`.
- If `enable_enforcement=true`, and a non-allowlisted source requests dangerous access to a protected PID,
  the driver returns `STATUS_ACCESS_DENIED` for that specific handle operation.

Start with enforcement disabled and validate stability on a VM. Build a conservative allowlist before enabling.


## Phase 5: Signer-based dynamic allowlist (driver enforcement)

Phase 5 upgrades enforcement from a static PID allowlist to a **signer-based dynamic allowlist**.

Design:
- Kernel driver enforces protected targets via `ObRegisterCallbacks`.
- When a non-allowlisted source requests dangerous access to a protected PID, the driver either:
  - **strips** dangerous rights (default), or
  - **denies** the handle open (optional; riskier).
- The driver emits a `HandleAccess` event with a `Decision` field (Allow/Stripped/Denied).
- User-mode receives the event, enriches the source process (path, signer, hash), and if the signer is trusted by policy,
  it **allowlists the PID dynamically** via `IOCTL_MINIEDR_ALLOWLIST_ADD`.

Configuration:
- `agent/config/driver_policy.json`
  - `enable_enforcement`: enable protect mode
  - `strip_instead_of_deny`: prefer stripping rights over denying
- `agent/config/signer_trust.json`
  - signer trust policy used to allowlist tools dynamically
