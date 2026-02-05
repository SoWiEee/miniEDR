#include "detection/rule_engine.h"
#include <cwctype>

#include "utils/encoding.h"
#include "utils/mini_json.h"
#include "utils/win_path.h"

#include <algorithm>
#include <fstream>
#include <regex>
#include <sstream>

namespace miniedr {

static std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(towlower(c));
    });
    return s;
}

bool RuleEngine::ContainsI(const std::wstring& haystack, const std::wstring& needle) {
    if (needle.empty()) return true;
    auto h = ToLower(haystack);
    auto n = ToLower(needle);
    return h.find(n) != std::wstring::npos;
}

static std::wstring EventTypeToString(EventType t) {
    switch (t) {
    case EventType::ProcessCreate: return L"ProcessCreate";
    case EventType::ProcessAccess: return L"ProcessAccess";
    case EventType::CreateRemoteThread: return L"CreateRemoteThread";
    case EventType::ImageLoad: return L"ImageLoad";
    case EventType::NetworkConnect: return L"NetworkConnect";
    case EventType::DnsQuery: return L"DnsQuery";
    case EventType::ScriptBlock: return L"ScriptBlock";
    case EventType::AmsiScan: return L"AmsiScan";
    case EventType::MemoryOperation: return L"MemoryOperation";
    case EventType::FileCreate: return L"FileCreate";
    case EventType::FileDelete: return L"FileDelete";
    case EventType::RegistrySetValue: return L"RegistrySetValue";
    default: return L"Unknown";
    }
}

std::wstring RuleEngine::GetFieldValue(const CanonicalEvent& ev, const std::wstring& field) {
    if (field == L"type") return EventTypeToString(ev.type);
    if (field == L"source") return ev.source;
    if (field == L"timestamp_utc") return ev.timestamp_utc;
    if (field == L"source_eid") return std::to_wstring(ev.source_eid);

    auto dot = field.find(L'.');
    if (dot == std::wstring::npos) return L"";

    auto root = field.substr(0, dot);
    auto rest = field.substr(dot + 1);

    if (root == L"proc") {
        if (rest == L"image") return ev.proc.image;
        if (rest == L"command_line") return ev.proc.command_line;
        if (rest == L"user") return ev.proc.user;
        if (rest == L"pid") return std::to_wstring(ev.proc.pid);
        if (rest == L"ppid") return std::to_wstring(ev.proc.ppid);
    }
    if (root == L"target") {
        if (rest == L"image") return ev.target.image;
        if (rest == L"pid") return std::to_wstring(ev.target.pid);
        if (rest == L"ppid") return std::to_wstring(ev.target.ppid);
    }
    if (root == L"fields") {
        auto it = ev.fields.find(rest);
        if (it != ev.fields.end()) return it->second;
    }
    return L"";
}

static bool EqualsI(const std::wstring& a, const std::wstring& b) {
    return ToLower(a) == ToLower(b);
}

bool RuleEngine::MatchCondition(const CanonicalEvent& ev, const Condition& c) {
    const auto actual = GetFieldValue(ev, c.field);

    if (c.op == L"equals_any") {
        for (const auto& v : c.values) {
            if (EqualsI(actual, v)) return true;
        }
        return false;
    }
    if (c.op == L"contains_any") {
        for (const auto& v : c.values) {
            if (ContainsI(actual, v)) return true;
        }
        return false;
    }
    if (c.op == L"regex_any") {
        for (const auto& v : c.values) {
            try {
                const std::wregex re(v, std::regex_constants::icase);
                if (std::regex_search(actual, re)) return true;
            } catch (...) {
                // Bad regex -> treat as non-match
            }
        }
        return false;
    }

    // Unknown operator
    return false;
}

static std::string ReadAll(const std::wstring& path_w) {
#ifdef _WIN32
    std::ifstream f(path_w, std::ios::binary);
#else
    std::ifstream f(WideToUtf8(path_w), std::ios::binary);
#endif
    if (!f) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static std::vector<std::wstring> JsonToWStringArray(const json::Value& v) {
    std::vector<std::wstring> out;
    if (!v.is_array()) return out;
    for (const auto& it : v.as_array()) {
        if (it.is_string()) out.push_back(Utf8ToWide(it.as_string()));
        else if (it.is_number()) out.push_back(std::to_wstring((uint64_t)it.as_number()));
    }
    return out;
}

std::vector<Rule> RuleEngine::LoadRulesFromJsonFile(const std::wstring& path) {
    std::vector<Rule> out;
    auto s = ReadAll(path);
    if (s.empty()) return out;

    json::Value doc;
    try {
        doc = json::parse(s);
    } catch (...) {
        return out;
    }
    if (!doc.is_object()) return out;

    const auto* rules_v = doc.get("rules");
    if (!rules_v || !rules_v->is_array()) return out;

    for (const auto& rv : rules_v->as_array()) {
        if (!rv.is_object()) continue;
        Rule r;
        if (auto* id = rv.get("id"); id && id->is_string()) r.id = Utf8ToWide(id->as_string());
        if (auto* title = rv.get("title"); title && title->is_string()) r.title = Utf8ToWide(title->as_string());
        if (auto* sev = rv.get("severity"); sev && sev->is_string()) r.severity = Utf8ToWide(sev->as_string());
        if (auto* sum = rv.get("summary"); sum && sum->is_string()) r.summary = Utf8ToWide(sum->as_string());

        // conditions: {"all":[{"field":"type","op":"equals_any","values":["ProcessCreate"]}, ...]}
        if (auto* conds = rv.get("all"); conds && conds->is_array()) {
            for (const auto& cv : conds->as_array()) {
                if (!cv.is_object()) continue;
                Condition c;
                if (auto* f = cv.get("field"); f && f->is_string()) c.field = Utf8ToWide(f->as_string());
                if (auto* op = cv.get("op"); op && op->is_string()) c.op = Utf8ToWide(op->as_string());
                if (auto* vals = cv.get("values"); vals) c.values = JsonToWStringArray(*vals);
                if (!c.field.empty() && !c.op.empty() && !c.values.empty()) r.all.push_back(std::move(c));
            }
        }
        if (!r.id.empty() && !r.title.empty() && !r.all.empty()) out.push_back(std::move(r));
    }
    return out;
}

std::vector<Rule> RuleEngine::BuiltinRules() {
    // Conservative triage signals. Keep these readable; move to JSON for real tuning.
    // NOTE: Like Phase 1, we do not enrich parent image yet, so chain-style rules are approximations.
    return {
        Rule{
            L"PROC-001",
            L"Suspicious script interpreter execution",
            L"Medium",
            L"A script interpreter or LOLBin executed (PowerShell/cmd/wscript/mshta). Review command line and parent lineage.",
            {
                {L"type", L"equals_any", {L"ProcessCreate"}},
                {L"proc.image", L"contains_any", {L"powershell.exe", L"pwsh.exe", L"wscript.exe", L"cscript.exe", L"cmd.exe", L"mshta.exe", L"rundll32.exe", L"regsvr32.exe"}}
            }
        },
        Rule{
            L"PROC-002",
            L"PowerShell encoded command",
            L"High",
            L"PowerShell execution with -enc/-EncodedCommand is commonly used to obfuscate payloads.",
            {
                {L"type", L"equals_any", {L"ProcessCreate"}},
                {L"proc.image", L"contains_any", {L"powershell.exe", L"pwsh.exe"}},
                {L"proc.command_line", L"regex_any", {LR"(\s-(enc|encodedcommand)\s)"}}
            }
        },
        Rule{
            L"INJ-001",
            L"High-rights process access (possible injection prep)",
            L"Medium",
            L"A process opened another process with broad access rights. This can be benign, but is also used for injection/hollowing workflows.",
            {
                {L"type", L"equals_any", {L"ProcessAccess"}},
                {L"fields.GrantedAccess", L"regex_any", {LR"(0x1f(f|F){4})", L"0x1fffff"}}
            }
        },
        Rule{
            L"INJ-002",
            L"CreateRemoteThread into another process",
            L"High",
            L"A process created a thread in another process. This is a strong indicator of code injection (review source/target images and start address).",
            {
                {L"type", L"equals_any", {L"CreateRemoteThread"}}
            }
        },
        Rule{
            L"IMG-001",
            L"Executable loads DLL from user-writable location",
            L"Medium",
            L"A process loaded a DLL from a user-writable directory (Temp/AppData). This can indicate DLL search order hijacking or sideloading.",
            {
                {L"type", L"equals_any", {L"ImageLoad"}},
                {L"fields.ImageLoaded", L"regex_any", {LR"(\\Users\\.*\\AppData\\)", LR"(\\Windows\\Temp\\)", LR"(\\Temp\\)"}}
            }
        },
        Rule{
            L"NET-001",
            L"Executable initiates network connection",
            L"Low",
            L"Process initiated a network connection. Use this for pivoting and enrichment (who connected where).",
            {
                {L"type", L"equals_any", {L"NetworkConnect"}},
                {L"fields.DestinationIp", L"regex_any", {L".+"}}
            }
        },
    };
}

RuleEngine::RuleEngine() {
    // Try to load rules from: <exe_dir>\\rules\\default_rules.json
    // Fallback: ./rules/default_rules.json
    // Else: built-ins.
    std::vector<std::wstring> candidates;
#ifdef _WIN32
    auto exe_dir = GetExecutableDirW();
    if (!exe_dir.empty()) {
        candidates.push_back(exe_dir + L"\\rules\\remote_rules.json");
        candidates.push_back(exe_dir + L"\\rules\\default_rules.json");
    }
#endif
    candidates.push_back(L"rules\\remote_rules.json");
    candidates.push_back(L"rules\\default_rules.json");
    candidates.push_back(L"default_rules.json");

    for (const auto& p : candidates) {
        auto loaded = LoadRulesFromJsonFile(p);
        if (!loaded.empty()) {
            rules_ = std::move(loaded);
            return;
        }
    }
    rules_ = BuiltinRules();
}

std::vector<Finding> RuleEngine::Evaluate(const CanonicalEvent& ev) const {
    std::vector<Finding> out;
    for (const auto& r : rules_) {
        bool ok = true;
        for (const auto& c : r.all) {
            if (!MatchCondition(ev, c)) { ok = false; break; }
        }
        if (!ok) continue;

        Finding f;
        f.rule_id = r.id;
        f.title = r.title;
        f.severity = r.severity.empty() ? L"Info" : r.severity;
        f.summary = r.summary;
        f.evidence = ev;
        out.push_back(std::move(f));
    }
    return out;
}

} // namespace miniedr
