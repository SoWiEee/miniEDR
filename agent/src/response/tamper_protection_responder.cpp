#include "response/tamper_protection_responder.h"
#ifdef _WIN32

#include <windows.h>

#include <algorithm>
#include <cwctype>

namespace miniedr {

namespace {

using NtSuspendProcessFn = LONG(NTAPI*)(HANDLE);

NtSuspendProcessFn ResolveNtSuspendProcess() {
    auto ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return nullptr;
    return reinterpret_cast<NtSuspendProcessFn>(GetProcAddress(ntdll, "NtSuspendProcess"));
}

std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(towlower(c));
    });
    return s;
}

} // namespace

TamperProtectionResponder::TamperProtectionResponder(TamperProtectionConfig cfg)
    : cfg_(std::move(cfg)) {}

bool TamperProtectionResponder::IsProtectedTarget(const CanonicalEvent& ev) const {
    if (cfg_.protected_process_names.empty()) return false;
    const auto target_image = ToLower(ev.target.image);
    const auto actor_image = ToLower(ev.proc.image);
    for (const auto& name : cfg_.protected_process_names) {
        auto lowered = ToLower(name);
        if (!target_image.empty() && target_image.find(lowered) != std::wstring::npos) return true;
        if (!actor_image.empty() && actor_image.find(lowered) != std::wstring::npos) return true;
    }
    return false;
}

ResponseAction TamperProtectionResponder::Handle(const EnrichedFinding& alert) {
    ResponseAction ra;
    ra.action = Name();

    if (!cfg_.enable) {
        ra.success = false;
        ra.message = L"tamper protection disabled";
        return ra;
    }

    if (!IsProtectedTarget(alert.evidence)) {
        ra.success = false;
        ra.message = L"no protected target";
        return ra;
    }

    DWORD pid = alert.evidence.proc.pid;
    ra.target = std::to_wstring(pid);
    if (pid == 0) {
        ra.success = false;
        ra.message = L"no pid in evidence";
        return ra;
    }

    HANDLE h = OpenProcess(PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!h) {
        ra.success = false;
        ra.message = L"OpenProcess failed";
        return ra;
    }

    if (cfg_.terminate_on_tamper) {
        BOOL ok = TerminateProcess(h, 1);
        CloseHandle(h);
        ra.success = ok ? true : false;
        ra.message = ok ? L"tamper source terminated" : L"TerminateProcess failed";
        return ra;
    }

    if (cfg_.suspend_on_tamper) {
        auto suspend = ResolveNtSuspendProcess();
        if (!suspend) {
            CloseHandle(h);
            ra.success = false;
            ra.message = L"NtSuspendProcess not available";
            return ra;
        }
        auto status = suspend(h);
        CloseHandle(h);
        ra.success = (status == 0);
        ra.message = ra.success ? L"tamper source suspended" : L"NtSuspendProcess failed";
        return ra;
    }

    CloseHandle(h);
    ra.success = false;
    ra.message = L"no tamper action configured";
    return ra;
}

} // namespace miniedr

#endif
