# MiniEDR

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/SoWiEee/miniEDR)

# Introduction

MiniEDR is a C++ Windows EDR starter project designed for cyber security learners who are new to Windows telemetry and detection engineering.
This is still an educational project. The goal is clarity and extensibility, not production completeness.

## Requirements

- Windows 10/11 x64
- Visual Studio 2022 with C++ workload
- CMake 3.21+
- Sysmon installed (Sysinternals)
- Administrator privileges recommended (Sysmon subscription and ETW kernel session typically require it)

## Build & Run

1. From a Developer PowerShell for VS
```bash
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```
2. Run MiniEDR (Administrator Recommended)
    - `build\bin\Release\miniedr.exe`
    - Optional flags:
        - `--no-sysmon` -> Disable Sysmon collector
        - `--no-etw`    -> Disable ETW kernel collector
3. Outputs
    - Console alerts
    - `alerts.jsonl` in the current working directory

# System Design

## Repository layout

- `agent/` user-mode agent code
  - `collectors/` Sysmon + ETW collectors
  - `pipeline/` canonical event schema + normalizer
  - `detection/` rule engine + correlator
  - `output/` alert sinks
  - `utils/` small utilities (encoding, JSON parser, path helpers)
- `tools/sysmon/` Sysmon configuration
- `rules/` default JSON ruleset

## 1. Telemetry (user mode)

### Sysmon collector

- Real-time subscription to Sysmon events
- Normalizes selected Sysmon events:
    - EID 1  ProcessCreate
    - EID 3  NetworkConnect
    - EID 7  ImageLoad
    - EID 8  CreateRemoteThread
    - EID 10 ProcessAccess
    - EID 11 FileCreate
    - EID 13 Registry value set
    - EID 22 DNS query
    - EID 23/26 File delete

> Sample Sysmon config is in `tools/sysmon/sysmonconfig.xml`.
> - Install Sysmon: `sysmon64.exe -accepteula -i tools\sysmon\sysmonconfig.xml`
> - Update config: `sysmon64.exe -c tools\sysmon\sysmonconfig.xml`
> This config is intentionally permissive for learning; expect noise. In real environments you should tune filters and add excludes.

### ETW collector (optional)

- Consumes the **NT Kernel Logger** in real time for:
    - Process events (ProcessGuid) → mapped to `ProcessCreate`
    - Image load events (ImageLoadGuid) → mapped to `ImageLoad`
- Subscribes to user-mode ETW providers for script + AMSI + memory signals:
    - `Microsoft-Windows-PowerShell` → `ScriptBlock`
    - `Microsoft-Windows-Antimalware-Scan-Interface` → `AmsiScan`
    - `Microsoft-Windows-Kernel-Memory` → `MemoryOperation`
    - `Microsoft-Windows-Threat-Intelligence` → `ThreatIntel`
    - `Microsoft-Windows-Kernel-Registry` → `RegistrySetValue`

> ETW collector is optional and can be disabled via `--no-etw` flag.

### Detours (user-mode API call)

- On-demand injection only (triggered by high/critical alerts) to keep overhead low.
- Hook DLL writes newline-delimited JSON to a named pipe (`\\.\pipe\MiniEDR.ApiHook`).
- Agent receives events via `ApiHookCollector` and normalizes them into `EventType::ApiCall`.
- Hooked APIs:
    - `CreateRemoteThread`
    - `WriteProcessMemory`
    - `VirtualAllocEx`
    - `OpenProcess` (high-rights only)
    - `NtCreateThreadEx`

Enable hooking:
- Edit `agent/config/hooking.json` and set `"enable_hooking": true`.
- Hook injection is triggered for **High/Critical** findings via `ApiHookInjectResponder`.

> You should build the hook DLL to `tools\bin\MiniEDR.ApiHookDll64.dll`.

### Kernel driver collector

The driver registers callbacks:
- Process create/exit: `PsSetCreateProcessNotifyRoutineEx`
- Image load: `PsSetLoadImageNotifyRoutine`
- Process handle audit: `ObRegisterCallbacks`

Kernel events are intentionally compact. After receiving a kernel event, the agent performs **best-effort enrichment**:
- Full image path (`QueryFullProcessImageName`)
- Command line (PEB read via `NtQueryInformationProcess` + `ReadProcessMemory`)
- User (`OpenProcessToken` + `LookupAccountSid`)
- Image hash (SHA-256)
- Authenticode signature verification and signer subject/issuer (best-effort)

Upgrades enforcement from a static PID allowlist to a **signer-based dynamic allowlist**.
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

## 2. Detection

- Data-driven JSON ruleset (`rules/default_rules.json`)
  - Simple condition model: `equals_any`, `contains_any`, `regex_any`
  - Field paths like `proc.image`, `proc.command_line`, `target.image`, `fields.GrantedAccess`, `type`
- Stateful correlation
  - CORR-INJ-001: `ProcessAccess (high-rights)` followed by `CreateRemoteThread` within a short window

### Output

- Console alerts
- JSONL alerts (`alerts.jsonl`) including:
  - Source, event id/opcode
  - Actor + Target process info (where available)
  - Up to a few event-specific fields
  - ECS/OCSF-aligned metadata blocks for easier downstream integration

## 3. Rules

- Default rules live here: `rules/default_rules.json`
- The agent attempts to load rules in this order:
    1. `<exe_dir>\rules\remote_rules.json` (if delivered by central control)
    2. `<exe_dir>\rules\default_rules.json`
    3. `.\rules\remote_rules.json`
    4. `.\rules\default_rules.json`
    5. `.\default_rules.json`
    6. Built-in fallback rules

> You can edit the JSON rules without rebuilding.

## 4. Scanners (on-demand)

- On-demand deep scans for already-alerted PIDs
- Config: `agent\config\scanners.json`
- Adapters for:
    - PE-sieve (single PID scan)
    - HollowsHunter (PID + directory + unique ID scan)
    - YARA (PID scan via CLI), bring your own rules at `rules\yara\`
- Each scan creates a unique folder under `scan_outputs/` by default.

> You should Download the latest releases of [PE-sieve](https://github.com/hasherezade/pe-sieve), [HollowsHunter](https://github.com/hasherezade/hollows_hunter), [Yara](https://github.com/VirusTotal/yara) and put the executables into `tools/bin/`.

## 5. Response

A response manager scaffold is added (currently off by default) to keep the core detection path safe and predictable.
Implemented example actions:
- terminate process for **Critical** alerts (when enabled)
- suspend process (for High/Critical, when enabled)
- quarantine file (for High/Critical, when enabled)
- tamper protection: terminate/suspend the source when it targets protected processes

Files:
- `agent/src/response/*`

> You can extend this with: suspend process, isolate host/network, quarantine file, block hash, etc.

## 6. Centralized control (optional)

- Event upload: alerts can be posted to a central service via HTTP.
- Policy delivery: download policy JSON (`agent\config\policy.json`) to tune response behavior on startup.
- Rule versioning: download rules with a `version` field and store to `rules\remote_rules.json` plus `rules\remote_rules.version`.

Config: `agent/config/central_config.json`

# Future Work & Integration Ideas

## YARA: add rule sources

- [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base)
- [InQuest/awesome-yara](https://github.com/InQuest/awesome-yara)

## Sandbox integration

Iintended design is “submit suspicious artifacts to an isolated analysis system” and ingest the report back into Evidence.

Will integrate [CAPE Sandbox](https://github.com/kevoreilly/CAPEv2)

Common EDR pattern:
- Endpoint flags a file/process → uploads sample to sandbox → receives behavioral report → correlates with host telemetry to confirm severity.
