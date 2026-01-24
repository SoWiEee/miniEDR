#include "detection/rule_engine.h"
#include <algorithm>

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

RuleEngine::RuleEngine() {
    // Baseline rules: common suspicious LOLBin chains (conservative).
    // These are *signals* for triage, not definitive malware verdicts.
    proc_create_rules_.push_back(ProcessCreateRule{
        L"PROC-001",
        L"Office spawns script interpreter",
        L"High",
        {L"winword.exe", L"excel.exe", L"powerpnt.exe", L"outlook.exe"},
        {L"powershell.exe", L"wscript.exe", L"cscript.exe", L"cmd.exe", L"mshta.exe"},
        {},
        L"An Office process spawned a script interpreter. This is frequently associated with phishing/macro execution."
    });

    proc_create_rules_.push_back(ProcessCreateRule{
        L"PROC-002",
        L"Browser spawns PowerShell",
        L"Medium",
        {L"chrome.exe", L"msedge.exe", L"firefox.exe"},
        {L"powershell.exe"},
        {},
        L"A browser process spawned PowerShell. Validate download origin and command line."
    });

    proc_create_rules_.push_back(ProcessCreateRule{
        L"PROC-003",
        L"PowerShell with encoded command",
        L"High",
        {},
        {L"powershell.exe", L"pwsh.exe"},
        {L"-enc", L"-encodedcommand"},
        L"PowerShell invoked with an encoded command. This is frequently used for obfuscation."
    });
}

std::vector<Finding> RuleEngine::Evaluate(const CanonicalEvent& ev) const {
    std::vector<Finding> out;
    if (ev.type != EventType::ProcessCreate) return out;

    // Phase 1 limitation: we don't yet enrich parent image reliably from Sysmon XML alone.
    // We still match on child image + cmdline, and we keep parent matching for future enrichment.
    for (const auto& r : proc_create_rules_) {
        bool child_ok = false;
        for (const auto& token : r.child_image_contains) {
            if (ContainsI(ev.proc.image, token)) { child_ok = true; break; }
        }
        if (!child_ok) continue;

        bool cmd_ok = r.cmdline_contains.empty();
        for (const auto& token : r.cmdline_contains) {
            if (ContainsI(ev.proc.command_line, token)) { cmd_ok = true; break; }
        }
        if (!cmd_ok) continue;

        Finding f;
        f.rule_id = r.id;
        f.title = r.title;
        f.severity = r.severity;
        f.summary = r.summary_template;
        f.evidence = ev;
        out.push_back(std::move(f));
    }
    return out;
}

} // namespace miniedr
