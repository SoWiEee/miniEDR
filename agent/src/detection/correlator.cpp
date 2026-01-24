#include "detection/correlator.h"
#include <cwctype>

#ifdef _WIN32
#include <windows.h>
#endif

namespace miniedr {

uint64_t Correlator::NowMs() {
#ifdef _WIN32
    return static_cast<uint64_t>(GetTickCount64());
#else
    return 0;
#endif
}

static std::wstring ToLower(std::wstring s) {
    for (auto& c : s) c = static_cast<wchar_t>(towlower(c));
    return s;
}

bool Correlator::IsHighRightsAccess(const std::wstring& granted_access) {
    // Sysmon EID10 GrantedAccess is usually a hex string like "0x1fffff".
    // We treat broad access masks as suspicious. This is a heuristic.
    auto s = ToLower(granted_access);
    return (s.find(L"0x1fffff") != std::wstring::npos) ||
           (s.find(L"0x1f0fff") != std::wstring::npos) ||
           (s.find(L"0x1f3fff") != std::wstring::npos);
}

std::vector<Finding> Correlator::Process(const CanonicalEvent& ev) {
    std::vector<Finding> out;
    const auto now = NowMs();

    // Expire old entries (simple linear scan; fine for a starter project).
    for (auto it = recent_access_.begin(); it != recent_access_.end(); ) {
        if (now - it->second.seen_ms > 15000) it = recent_access_.erase(it);
        else ++it;
    }

    if (ev.type == EventType::ProcessAccess) {
        auto it = ev.fields.find(L"GrantedAccess");
        if (it != ev.fields.end() && IsHighRightsAccess(it->second)) {
            Key k{ev.proc.pid, ev.target.pid};
            recent_access_[k] = Recent{now, ev};
        }
        return out;
    }

    if (ev.type == EventType::CreateRemoteThread) {
        Key k{ev.proc.pid, ev.target.pid};
        auto it = recent_access_.find(k);
        if (it != recent_access_.end() && (now - it->second.seen_ms) <= 10000) {
            Finding f;
            f.rule_id = L"CORR-INJ-001";
            f.title = L"Process injection pattern: high-rights ProcessAccess -> CreateRemoteThread";
            f.severity = L"High";
            f.summary = L"Observed a high-rights process handle open (Sysmon EID10) followed shortly by CreateRemoteThread (Sysmon EID8). This is a strong injection signal; triage source/target images and start address.";
            f.evidence = ev; // use the later event as primary evidence
            out.push_back(std::move(f));
        }
        return out;
    }

    return out;
}

} // namespace miniedr