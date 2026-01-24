#include "pipeline/normalizer.h"

#include <regex>

namespace miniedr {

std::wstring Normalizer::ExtractDataField(const std::wstring& xml, const std::wstring& name) {
    // Matches: <Data Name="Image">C:\...\something.exe</Data>
    // Note: This is a pragmatic extractor, not a full XML parser.
    const std::wregex re(LR"(<Data\s+Name=")" + name + LR"(">(.*?)</Data>)", std::regex_constants::icase);
    std::wsmatch m;
    if (std::regex_search(xml, m, re) && m.size() >= 2) {
        return m[1].str();
    }
    return L"";
}

uint32_t Normalizer::ExtractUIntField(const std::wstring& xml, const std::wstring& name) {
    auto s = ExtractDataField(xml, name);
    if (s.empty()) return 0;
    try {
        return static_cast<uint32_t>(std::stoul(s));
    } catch (...) {
        return 0;
    }
}

std::wstring Normalizer::ExtractSystemTimeUtc(const std::wstring& xml) {
    // Matches: <TimeCreated SystemTime="2026-01-24T12:34:56.1234567Z" />
    const std::wregex re(LR"(<TimeCreated\s+SystemTime="([^"]+)");
    std::wsmatch m;
    if (std::regex_search(xml, m, re) && m.size() >= 2) {
        return m[1].str();
    }
    return L"";
}

static void FillActorFromSysmonFields(CanonicalEvent& ev, const std::wstring& xml) {
    ev.proc.pid = Normalizer::ExtractUIntField(xml, L"ProcessId");
    ev.proc.ppid = Normalizer::ExtractUIntField(xml, L"ParentProcessId");
    ev.proc.image = Normalizer::ExtractDataField(xml, L"Image");
    ev.proc.command_line = Normalizer::ExtractDataField(xml, L"CommandLine");
    ev.proc.user = Normalizer::ExtractDataField(xml, L"User");
}

std::optional<CanonicalEvent> Normalizer::NormalizeSysmonXml(uint32_t sysmon_eid, const std::wstring& xml) {
    CanonicalEvent ev;
    ev.source = L"sysmon";
    ev.source_eid = sysmon_eid;
    ev.raw_xml = xml;
    ev.timestamp_utc = ExtractSystemTimeUtc(xml);

    switch (sysmon_eid) {
    case 1: { // ProcessCreate
        ev.type = EventType::ProcessCreate;
        FillActorFromSysmonFields(ev, xml);
        // ParentProcessId exists; parent image isn't in Sysmon EID1 by default without ProcessGuid lookup.
        return ev;
    }
    case 3: { // NetworkConnect
        ev.type = EventType::NetworkConnect;
        FillActorFromSysmonFields(ev, xml);
        ev.fields[L"Protocol"] = ExtractDataField(xml, L"Protocol");
        ev.fields[L"Initiated"] = ExtractDataField(xml, L"Initiated");
        ev.fields[L"SourceIp"] = ExtractDataField(xml, L"SourceIp");
        ev.fields[L"SourcePort"] = ExtractDataField(xml, L"SourcePort");
        ev.fields[L"DestinationIp"] = ExtractDataField(xml, L"DestinationIp");
        ev.fields[L"DestinationPort"] = ExtractDataField(xml, L"DestinationPort");
        ev.fields[L"DestinationHostname"] = ExtractDataField(xml, L"DestinationHostname");
        return ev;
    }
    case 7: { // ImageLoad
        ev.type = EventType::ImageLoad;
        FillActorFromSysmonFields(ev, xml);
        ev.fields[L"ImageLoaded"] = ExtractDataField(xml, L"ImageLoaded");
        ev.fields[L"Hashes"] = ExtractDataField(xml, L"Hashes");
        ev.fields[L"Signed"] = ExtractDataField(xml, L"Signed");
        ev.fields[L"SignatureStatus"] = ExtractDataField(xml, L"SignatureStatus");
        return ev;
    }
    case 8: { // CreateRemoteThread
        ev.type = EventType::CreateRemoteThread;
        // Sysmon uses Source* and Target* field names.
        ev.proc.pid = ExtractUIntField(xml, L"SourceProcessId");
        ev.proc.image = ExtractDataField(xml, L"SourceImage");
        ev.target.pid = ExtractUIntField(xml, L"TargetProcessId");
        ev.target.image = ExtractDataField(xml, L"TargetImage");
        ev.fields[L"NewThreadId"] = ExtractDataField(xml, L"NewThreadId");
        ev.fields[L"StartAddress"] = ExtractDataField(xml, L"StartAddress");
        ev.fields[L"StartModule"] = ExtractDataField(xml, L"StartModule");
        ev.fields[L"StartFunction"] = ExtractDataField(xml, L"StartFunction");
        return ev;
    }
    case 10: { // ProcessAccess
        ev.type = EventType::ProcessAccess;
        ev.proc.pid = ExtractUIntField(xml, L"SourceProcessId");
        ev.proc.image = ExtractDataField(xml, L"SourceImage");
        ev.target.pid = ExtractUIntField(xml, L"TargetProcessId");
        ev.target.image = ExtractDataField(xml, L"TargetImage");
        ev.fields[L"GrantedAccess"] = ExtractDataField(xml, L"GrantedAccess");
        ev.fields[L"CallTrace"] = ExtractDataField(xml, L"CallTrace");
        return ev;
    }
    case 11: { // FileCreate
        ev.type = EventType::FileCreate;
        FillActorFromSysmonFields(ev, xml);
        ev.fields[L"TargetFilename"] = ExtractDataField(xml, L"TargetFilename");
        ev.fields[L"CreationUtcTime"] = ExtractDataField(xml, L"CreationUtcTime");
        return ev;
    }
    case 13: { // Registry value set
        ev.type = EventType::RegistrySetValue;
        FillActorFromSysmonFields(ev, xml);
        ev.fields[L"TargetObject"] = ExtractDataField(xml, L"TargetObject");
        ev.fields[L"Details"] = ExtractDataField(xml, L"Details");
        return ev;
    }
    case 22: { // DNS query
        ev.type = EventType::DnsQuery;
        FillActorFromSysmonFields(ev, xml);
        ev.fields[L"QueryName"] = ExtractDataField(xml, L"QueryName");
        ev.fields[L"QueryResults"] = ExtractDataField(xml, L"QueryResults");
        ev.fields[L"QueryStatus"] = ExtractDataField(xml, L"QueryStatus");
        return ev;
    }
    case 23: // FileDelete (older)
    case 26: { // FileDeleteDetected (newer)
        ev.type = EventType::FileDelete;
        FillActorFromSysmonFields(ev, xml);
        ev.fields[L"TargetFilename"] = ExtractDataField(xml, L"TargetFilename");
        return ev;
    }
    default:
        return std::nullopt;
    }
}

} // namespace miniedr
