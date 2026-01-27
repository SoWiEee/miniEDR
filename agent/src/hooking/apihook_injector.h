#pragma once
#ifdef _WIN32
#include <string>
#include <windows.h>

namespace miniedr {

struct HookingConfig {
    bool enable_hooking = false;
    bool inject_on_high = true;
    std::wstring hook_dll_path = L"tools\\bin\\MiniEDR.ApiHookDll64.dll";
};

HookingConfig LoadHookingConfig(const std::wstring& path);

// x64-only best-effort injection. Fails open.
bool InjectHookDll(uint32_t pid, const std::wstring& dll_path);

} // namespace miniedr
#endif
