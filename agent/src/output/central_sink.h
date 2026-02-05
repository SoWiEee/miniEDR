#pragma once
#include "output/alert_sinks.h"
#include "control/central_manager.h"

namespace miniedr {

class CentralUploadSink : public IAlertSink {
public:
    explicit CentralUploadSink(CentralManager& manager);

    void Emit(const Finding& f) override;
    void EmitEnriched(const EnrichedFinding& f) override;

private:
    CentralManager& manager_;
};

} // namespace miniedr
