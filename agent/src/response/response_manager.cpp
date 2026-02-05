#include "response/response_manager.h"
#include "response/process_responder.h"
#include "response/process_suspend_responder.h"
#include "response/file_quarantine_responder.h"
#include "response/tamper_protection_responder.h"
#include "response/apihook_responder.h"
#include <algorithm>
#include <cwctype>

namespace miniedr {

static std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c){ return (wchar_t)towlower(c); });
    return s;
}

ResponseManager::ResponseManager(ResponseConfig cfg) : cfg_(cfg) {
#ifdef _WIN32
    responders_.push_back(std::make_unique<ProcessTerminateResponder>());
    responders_.push_back(std::make_unique<ProcessSuspendResponder>());
    responders_.push_back(std::make_unique<FileQuarantineResponder>());
    responders_.push_back(std::make_unique<TamperProtectionResponder>(TamperProtectionConfig{
        cfg_.enable_tamper_protection,
        cfg_.tamper_terminate_on_detect,
        cfg_.tamper_suspend_on_detect,
        cfg_.protected_process_names
    }));
    responders_.push_back(std::make_unique<ApiHookInjectResponder>(cfg_.hooking));
#endif
}

std::vector<ResponseAction> ResponseManager::Handle(const EnrichedFinding& alert) {
    std::vector<ResponseAction> out;
    if (!cfg_.enable_response) return out;

    auto sev = ToLower(alert.severity);
    bool is_critical = (sev == L"critical");
    bool is_high = (sev == L"high");

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
    if ((is_high || is_critical) && cfg_.auto_suspend_on_high) {
        for (auto& r : responders_) {
            if (r->Name() == L"suspend_process") {
                out.push_back(r->Handle(alert));
            }
        }
    }
    if ((is_high || is_critical) && cfg_.auto_quarantine_on_high) {
        for (auto& r : responders_) {
            if (r->Name() == L"quarantine_file") {
                out.push_back(r->Handle(alert));
            }
        }
    }
    if (cfg_.enable_tamper_protection) {
        for (auto& r : responders_) {
            if (r->Name() == L"tamper_protection") {
                auto action = r->Handle(alert);
                if (action.success) out.push_back(action);
            }
        }
    }
    return out;
}

} // namespace miniedr
