#pragma once
#ifdef _WIN32
#include "response/responder_iface.h"

namespace miniedr {

class ProcessTerminateResponder : public IResponder {
public:
    std::wstring Name() const override { return L"terminate_process"; }
    ResponseAction Handle(const EnrichedFinding& alert) override;
};

} // namespace miniedr
#endif
