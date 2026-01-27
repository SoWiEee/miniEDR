#include "response/apihook_responder.h"
#ifdef _WIN32

#include <filesystem>

namespace fs = std::filesystem;

namespace miniedr {

ApiHookInjectResponder::ApiHookInjectResponder(HookingConfig cfg) : cfg_(std::move(cfg)) {}

ResponseAction ApiHookInjectResponder::Handle(const EnrichedFinding& alert) {
    ResponseAction a;
    a.action = Name();
    a.target = std::to_wstring(alert.evidence.proc.pid);

    if (!cfg_.enable_hooking) {
        a.success = false;
        a.message = L"hooking disabled (agent/config/hooking.json)";
        return a;
    }
    if (!cfg_.inject_on_high) {
        a.success = false;
        a.message = L"inject_on_high disabled";
        return a;
    }

    // Only inject for High/Critical (best effort)
    auto sev = alert.severity;
    for (auto& c : sev) c = (wchar_t)towlower(c);
    if (!(sev == L"high" || sev == L"critical")) {
        a.success = false;
        a.message = L"severity not high/critical";
        return a;
    }

    uint32_t pid = alert.evidence.proc.pid;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (injected_.count(pid)) {
            a.success = true;
            a.message = L"already injected";
            return a;
        }
    }

    fs::path dll = cfg_.hook_dll_path;
    if (!fs::exists(dll)) {
        a.success = false;
        a.message = L"hook dll not found: " + cfg_.hook_dll_path;
        return a;
    }

    bool ok = InjectHookDll(pid, dll.wstring());
    a.success = ok;
    a.message = ok ? L"injected hook dll" : L"injection failed (insufficient rights / wow64 / protected process)";
    if (ok) {
        std::lock_guard<std::mutex> lk(mu_);
        injected_.insert(pid);
    }
    return a;
}

} // namespace miniedr
#endif
