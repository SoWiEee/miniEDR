#pragma once
#ifdef _WIN32
#include <string>
#include <unordered_map>

namespace miniedr {

struct XmlEventParseResult {
    bool ok = false;
    std::wstring event_id;            // <EventID>
    std::wstring system_time_utc;     // <TimeCreated SystemTime="...Z">
    std::unordered_map<std::wstring, std::wstring> data; // <Data Name="X">VALUE</Data>
    std::wstring error;
};

// Parse Windows Event Log XML (EvtRenderEventXml output) using XmlLite (IXmlReader).
// This is used to replace Phase 1/2 regex parsing with stronger, schema-like extraction.
XmlEventParseResult ParseWindowsEventXml(const std::wstring& xml);

} // namespace miniedr
#endif
