#pragma once
#ifdef _WIN32

#include "response/responder_iface.h"

namespace miniedr {

class FileQuarantineResponder : public IResponder {
public:
    std::wstring Name() const override { return L"quarantine_file"; }
    ResponseAction Handle(const EnrichedFinding& alert) override;
};

} // namespace miniedr

#endif
