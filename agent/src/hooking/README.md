Phase 3 note:
Hooking is intentionally **disabled by default** because it can break compatibility and is easily abused.
This folder provides interfaces/placeholders for future work:

- user-mode API hooking (e.g., via MinHook/Detours) for research-only telemetry
- ETW/Kernel callbacks are preferred when possible

If you add a hooking library, keep it optional, auditable, and guarded behind build flags.
