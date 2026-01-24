#include "pipeline/normalizer.h"

#include <regex>
#include <sstream>

namespace miniedr {

static std::wstring ExtractDataField(const std::wstring& xml, const std::wstring& name) {
    // Matches: <Data Name="Image">C:\...\something.exe</Data>
    // Note: This is a pragmatic Phase-1 extractor, not a full XML parser.
    const std::wregex re(LR"(<Data\s+Name=")" + name + LR"(">(.*?)</Data>)", std::regex_constants::icase);
    std::wsmatch m;
    if (std::regex_search(xml, m, re) && m.size() >= 2) {
        return m[1].str();
    }
    return L"";
}

static uint32_t ExtractUIntField(const std::wstring& xml, const std::wstring& name) {
    auto s = ExtractDataField(xml, name);
    if (s.empty()) return 0;
    try {
        return static_cast<uint32_t>(std::stoul(s));
    } catch (...) {
        return 0;
    }
}

static std::wstring ExtractSystemTimeUtc(const std::wstring& xml) {
    // Matches: <TimeCreated SystemTime="2026-01-24T12:34:56.1234567Z" />
    const std::wregex re(LR"(<TimeCreated\s+SystemTime="([^"]+)");
    std::wsmatch m;
    if (std::regex_search(xml, m, re) && m.size() >= 2) {
        return m[1].str();
    }
    return L"";
}

std::optional<CanonicalEvent> Normalizer::NormalizeSysmonXml(uint32_t sysmon_eid, const std::wstring& xml) {
    CanonicalEvent ev;
    ev.source = L"sysmon";
    ev.source_eid = sysmon_eid;
    ev.raw_xml = xml;
    ev.timestamp_utc = ExtractSystemTimeUtc(xml);

    if (sysmon_eid == 1) {
        ev.type = EventType::ProcessCreate;
        ev.proc.pid = ExtractUIntField(xml, L"ProcessId");
        ev.proc.ppid = ExtractUIntField(xml, L"ParentProcessId");
        ev.proc.image = ExtractDataField(xml, L"Image");
        ev.proc.command_line = ExtractDataField(xml, L"CommandLine");
        ev.proc.user = ExtractDataField(xml, L"User");
        return ev;
    }

    // Phase 1: only ProcessCreate rules are implemented.
    return std::nullopt;
}

} // namespace miniedr
