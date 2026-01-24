#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace miniedr {

enum class EventType {
    Unknown = 0,
    ProcessCreate,     // Sysmon EID 1
    ImageLoad,         // Sysmon EID 7 (future)
    NetworkConnect,    // Sysmon EID 3 (future)
};

struct ProcessInfo {
    uint32_t pid = 0;
    uint32_t ppid = 0;
    std::wstring image;        // full path if available
    std::wstring command_line;
    std::wstring user;
};

struct CanonicalEvent {
    EventType type = EventType::Unknown;
    std::wstring timestamp_utc;  // ISO 8601 string, if available
    ProcessInfo proc;

    // source metadata
    std::wstring source;         // e.g. "sysmon"
    uint32_t source_eid = 0;
    std::wstring raw_xml;        // kept for evidence/debugging in Phase 1
};

struct Finding {
    std::wstring rule_id;
    std::wstring title;
    std::wstring severity; // Info/Low/Medium/High/Critical
    std::wstring summary;
    CanonicalEvent evidence;
};

} // namespace miniedr
