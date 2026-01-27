Phase 6: Detours-based API hooking (research-only)
==================================================

This project includes optional support for user-mode API call telemetry using Microsoft Detours.

Why optional?
- User-mode hooks are fragile (compatibility risk) and can be bypassed (direct syscalls, unhooking).
- Prefer ETW + kernel callbacks when possible.

Components
- Hook DLL (x64): `hooks/MiniEDR_ApiHookDll64` (built only when enabled).
- Named pipe: `\\.\pipe\MiniEDR.ApiHook` (DLL writes newline-delimited JSON).
- Agent collector: `ApiHookCollector` converts messages into `EventType::ApiCall`.

Injection strategy
- On-demand only: when the engine emits High/Critical alerts, `ApiHookInjectResponder` tries to inject the Hook DLL.
- x64 only: WOW64 targets are skipped.

Detours references
- Transaction model: `DetourTransactionBegin` + `DetourAttach`. citeturn0search0turn0search8
- Withdll sample uses `DetourCreateProcessWithDlls` and requires the DLL export ordinal #1. citeturn0search5

Hardening ideas (future work)
- Add per-process opt-in/TTL for injected PIDs.
- Add allowlist/denylist by signer (reuse Phase 5 signer trust).
- Add stack hashing (RtlCaptureStackBackTrace) but keep it cheap.
