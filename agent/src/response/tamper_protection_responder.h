#pragma once
#ifdef _WIN32

#include "response/responder_iface.h"

#include <string>
#include <vector>

namespace miniedr {

struct TamperProtectionConfig {
    bool enable = true;
    bool terminate_on_tamper = true;
    bool suspend_on_tamper = false;
    std::vector<std::wstring> protected_process_names;
};

class TamperProtectionResponder : public IResponder {
public:
    explicit TamperProtectionResponder(TamperProtectionConfig cfg);
    std::wstring Name() const override { return L"tamper_protection"; }
    ResponseAction Handle(const EnrichedFinding& alert) override;

private:
    TamperProtectionConfig cfg_;
    bool IsProtectedTarget(const CanonicalEvent& ev) const;
};

} // namespace miniedr

#endif
