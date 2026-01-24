#pragma once
#include "pipeline/event_types.h"
#include <string>

namespace miniedr {

struct ResponseAction {
    std::wstring action;   // "terminate_process", "suspend_process", "quarantine_file", ...
    std::wstring target;   // pid or path
    bool success = false;
    std::wstring message;
};

class IResponder {
public:
    virtual ~IResponder() = default;
    virtual std::wstring Name() const = 0;
    virtual ResponseAction Handle(const EnrichedFinding& alert) = 0;
};

} // namespace miniedr
