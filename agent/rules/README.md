Phase 1 note:
- Rules are currently compiled into `RuleEngine` for maximum approachability.
- In Phase 2, we will move to a data-driven ruleset (YAML/JSON) loaded from this folder.


### ApiCall events (Phase 6)

If you enable Detours hooking, the agent will emit `EventType=ApiCall` events with fields like:
- `api`: OpenProcess / VirtualAllocEx / WriteProcessMemory / VirtualProtectEx / CreateRemoteThread
- `size`, `desired_access`, `win32_error`, `tid`

Suggested correlation (future rule-engine upgrade):
- Injection chain within a short window: OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread
