#pragma once
#ifdef _WIN32
#include "response/responder_iface.h"
#include "hooking/apihook_injector.h"
#include <unordered_set>
#include <mutex>

namespace miniedr {

// On-demand injection responder: inject the ApiHook DLL into an alerted PID.
// Intended for research/telemetry only; disabled by default.
class ApiHookInjectResponder : public IResponder {
public:
    explicit ApiHookInjectResponder(HookingConfig cfg);
    std::wstring Name() const override { return L"inject_apihook"; }
    ResponseAction Handle(const EnrichedFinding& alert) override;

private:
    HookingConfig cfg_;
    std::mutex mu_;
    std::unordered_set<uint32_t> injected_;
};

} // namespace miniedr
#endif
