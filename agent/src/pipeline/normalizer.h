#pragma once
#include "event_types.h"
#include <optional>
#include <string>

namespace miniedr {

// Normalizes Sysmon events by rendering XML via EvtRender(..., EvtRenderEventXml)
// and then extracting a small subset of fields from the XML.
//
// Phase 1: Sysmon EID 1 only.
// Phase 2: Adds more Sysmon IDs (3/7/8/10/11/13/22/23) and fills CanonicalEvent::fields
// for event-specific attributes.
//
class Normalizer {
public:
    std::optional<CanonicalEvent> NormalizeSysmonXml(uint32_t sysmon_eid, const std::wstring& xml);

    // Exposed for small helper functions in the normalizer implementation.
    static std::wstring ExtractDataField(const std::wstring& xml, const std::wstring& name);
    static uint32_t ExtractUIntField(const std::wstring& xml, const std::wstring& name);
    static std::wstring ExtractSystemTimeUtc(const std::wstring& xml);
};

} // namespace miniedr
