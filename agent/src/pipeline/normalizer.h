#pragma once
#include "event_types.h"
#include <optional>
#include <string>

namespace miniedr {

// In Phase 1 we normalize Sysmon events by rendering XML via EvtRender(..., EvtRenderEventXml)
// and then extracting a small subset of fields from the XML.
//
// This is intentionally conservative: it keeps the raw XML to preserve evidence,
// and extracts only what we need for baseline rules (image + command line + PID/PPID).
//
class Normalizer {
public:
    std::optional<CanonicalEvent> NormalizeSysmonXml(uint32_t sysmon_eid, const std::wstring& xml);
};

} // namespace miniedr
