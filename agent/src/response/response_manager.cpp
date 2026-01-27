#include "response/response_manager.h"
#include "response/process_responder.h"
#include "response/apihook_responder.h"
#include <algorithm>

namespace miniedr {

static std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c){ return (wchar_t)towlower(c); });
    return s;
}

ResponseManager::ResponseManager(ResponseConfig cfg) : cfg_(cfg) {
#ifdef _WIN32
    responders_.push_back(std::make_unique<ProcessTerminateResponder>());
    responders_.push_back(std::make_unique<ApiHookInjectResponder>(cfg_.hooking));
#endif
}

std::vector<ResponseAction> ResponseManager::Handle(const EnrichedFinding& alert) {
    std::vector<ResponseAction> out;
    if (!cfg_.enable_response) return out;

    auto sev = ToLower(alert.severity);
    bool is_critical = (sev == L"critical");

    // Phase 6: on-demand API hooking injection
    for (auto& r : responders_) {
        if (r->Name() == L"inject_apihook") out.push_back(r->Handle(alert));
    }

    if (is_critical && cfg_.auto_terminate_on_critical) {
        for (auto& r : responders_) {
            if (r->Name() == L"terminate_process") {
                out.push_back(r->Handle(alert));
            }
        }
    }
    return out;
}

} // namespace miniedr
