#pragma once
#include "response/responder_iface.h"
#include <memory>
#include <string>
#include "hooking/apihook_injector.h"

#include <vector>

namespace miniedr {

struct ResponseConfig {
    bool enable_response = false;
    bool auto_terminate_on_critical = false;
    bool auto_suspend_on_high = false;
    bool auto_quarantine_on_high = false;
    bool enable_tamper_protection = true;
    bool tamper_terminate_on_detect = true;
    bool tamper_suspend_on_detect = false;
    std::vector<std::wstring> protected_process_names{
        L"miniedr.exe"
    };
    HookingConfig hooking{};
};

class ResponseManager {
public:
    explicit ResponseManager(ResponseConfig cfg);
    std::vector<ResponseAction> Handle(const EnrichedFinding& alert);

private:
    ResponseConfig cfg_;
    std::vector<std::unique_ptr<IResponder>> responders_;
};

} // namespace miniedr
