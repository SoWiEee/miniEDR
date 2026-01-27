#pragma once
#include "response/responder_iface.h"
#include <memory>
#include "hooking/apihook_injector.h"

#include <vector>

namespace miniedr {

struct ResponseConfig {
    bool enable_response = false;
    bool auto_terminate_on_critical = false;
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
