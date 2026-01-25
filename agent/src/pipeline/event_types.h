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

    // Phase 4+: enrichment fields (best-effort)
    std::wstring image_sha256;       // SHA-256 of image file (if resolved)
    std::wstring signer_subject;     // leaf cert subject (if Authenticode verified)
    std::wstring signer_issuer;      // leaf cert issuer
    bool signer_trusted = false;     // signature verification passed
    bool signer_is_microsoft = false;
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

struct ScannerResult {
    std::wstring scanner;        // e.g. "pe-sieve", "hollows_hunter"
    bool executed = false;        // tool launched successfully
    bool suspicious = false;      // tool reported anomalies
    int exit_code = -1;           // process exit code
    std::wstring output_dir;      // where reports/dumps were written
    std::wstring summary;         // short human-readable summary
    std::wstring raw_report_path; // primary JSON report path if found
};

struct EnrichedFinding : public Finding {
    std::vector<ScannerResult> scans;
};

} // namespace miniedr
