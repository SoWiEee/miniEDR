#pragma once
#ifdef _WIN32
#include "pipeline/event_types.h"

namespace miniedr {

class ProcessEnricher {
public:
    // Best-effort enrichment for proc and target fields.
    // Safe to call repeatedly; it only fills missing fields where possible.
    void Enrich(CanonicalEvent& ev) const;

private:
    static void EnrichOne(ProcessInfo& p);
};

} // namespace miniedr
#endif
