#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace miniedr {

enum class EventType {
    Unknown = 0,

    // Process lifecycle
    ProcessCreate,        // Sysmon EID 1 (and ETW process start mapped here)

    // Process interaction / injection signals
    ProcessAccess,        // Sysmon EID 10
    CreateRemoteThread,   // Sysmon EID 8

    // Execution / loading / network
    ImageLoad,            // Sysmon EID 7
    NetworkConnect,       // Sysmon EID 3
    DnsQuery,             // Sysmon EID 22

    // Filesystem
    FileCreate,           // Sysmon EID 11
    FileDelete,           // Sysmon EID 23/26 (depending on Sysmon version/config)

    // Registry
    RegistrySetValue,     // Sysmon EID 13
};

struct ProcessInfo {
    uint32_t pid = 0;
    uint32_t ppid = 0;
    std::wstring image;        // full path if available
    std::wstring command_line;
    std::wstring user;
};

// A small canonical schema we can use across multiple telemetry sources.
// Phase 1 used only (source=sysmon, eid=1) and kept raw XML as evidence.
// Phase 2 expands to more Sysmon event IDs and adds an optional target process +
// a generic key/value map for additional fields.
struct CanonicalEvent {
    EventType type = EventType::Unknown;
    std::wstring timestamp_utc;  // ISO 8601 string, if available

    // "Actor" process (the process that performed the action).
    ProcessInfo proc;

    // Optional "target" process (used for injection-style events).
    ProcessInfo target;

    // source metadata
    std::wstring source;         // e.g. "sysmon" / "etw"
    uint32_t source_eid = 0;

    // Kept for evidence/debugging (Sysmon events).
    std::wstring raw_xml;

    // Extra fields for event-specific attributes.
    // Examples: GrantedAccess, StartAddress, DestinationIp, QueryName, TargetFilename...
    std::unordered_map<std::wstring, std::wstring> fields;
};

struct Finding {
    std::wstring rule_id;
    std::wstring title;
    std::wstring severity; // Info/Low/Medium/High/Critical
    std::wstring summary;
    CanonicalEvent evidence;
};

} // namespace miniedr
