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

> ETW collector is optional and can be disabled via `--no-etw` flag.

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

## 3. Rules

- Default rules live here: `rules/default_rules.json`
- The agent attempts to load rules in this order:
    1. `<exe_dir>\rules\default_rules.json`
    2. `.\rules\default_rules.json`
    3. `.\default_rules.json`
    4. Built-in fallback rules

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
Implemented example action:
- terminate process for **Critical** alerts (when enabled)

Files:
- `agent/src/response/*`

You can extend this with: suspend process, isolate host/network, quarantine file, block hash, etc.

## Repository layout

- `agent/` user-mode agent code
  - `collectors/` Sysmon + ETW collectors
  - `pipeline/` canonical event schema + normalizer
  - `detection/` rule engine + correlator
  - `output/` alert sinks
  - `utils/` small utilities (encoding, JSON parser, path helpers)
- `tools/sysmon/` Sysmon configuration
- `rules/` default JSON ruleset

## Phase 5: Signer-based dynamic allowlist (driver enforcement)




## Phase 6: Optional user-mode API call telemetry (Detours)

MiniEDR now includes an **optional Detours-based Hook DLL (x64 only)** for research-grade API telemetry. It is **disabled by default** because user-mode hooking is fragile and can break compatibility.

Design goals:
- On-demand injection only (triggered by high/critical alerts) to keep overhead low.
- Hook DLL writes newline-delimited JSON to a named pipe (`\\.\pipe\MiniEDR.ApiHook`).
- Agent receives events via `ApiHookCollector` and normalizes them into `EventType::ApiCall`.

Build Detours + Hook DLL:
1) Clone Microsoft Detours (MIT): build x64 to produce `detours.h` and `detours.lib`. citeturn0search16turn0search4
2) Configure CMake (example):
   - `-DMINIEDR_BUILD_APIOOK_DLL=ON -DDETOURS_ROOT=<path-to-detours> -DDETOURS_LIB=<path-to-detours.lib>`
3) Copy the built DLL to: `tools\bin\MiniEDR.ApiHookDll64.dll`

Detours API references used:
- Hook installation via transactions: `DetourTransactionBegin`, `DetourAttach`, `DetourTransactionCommit`. citeturn0search0turn0search8
- Process creation with injected DLLs (Detours sample `withdll`): `DetourCreateProcessWithDlls`. citeturn0search1turn0search5

Enable hooking:
- Edit `agent/config/hooking.json` and set `"enable_hooking": true`.
- Hook injection is triggered for **High/Critical** findings via `ApiHookInjectResponder`.


## YARA: rule sources and safe usage

MiniEDR can run YARA scans on-demand using `tools\bin\yara64.exe` against an alerted PID.

Recommended open rule sources (start conservative):
- Neo23x0 / signature-base (rules used by LOKI/THOR scanners): citeturn0search3turn0search18
- InQuest awesome-yara (curated list of high-quality rule sets/tools): citeturn0search2

Operational tips:
- Treat public YARA rules as *untrusted input*; review + tune to your environment.
- Expect false positives. Use your signer-based allowlist and evidence enrichment (hash/signer/path) to triage.


## Sandbox integration (concept)

MiniEDR does not ship a full sandbox, but the intended design is “submit suspicious artifacts to an isolated analysis system” and ingest the report back into Evidence.

Open-source sandboxes you can integrate:
- Cuckoo Sandbox: open-source automated malware analysis system. citeturn1search15turn1search2
- CAPE Sandbox: actively developed open-source malware sandbox derived from Cuckoo. citeturn1search3turn1search6turn1search12

Common EDR pattern:
- Endpoint flags a file/process → uploads sample to sandbox → receives behavioral report → correlates with host telemetry to confirm severity.
