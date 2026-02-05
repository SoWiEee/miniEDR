#include "response/process_suspend_responder.h"
#ifdef _WIN32

#include <windows.h>

namespace miniedr {

using NtSuspendProcessFn = LONG(NTAPI*)(HANDLE);

static NtSuspendProcessFn ResolveNtSuspendProcess() {
    auto ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return nullptr;
    return reinterpret_cast<NtSuspendProcessFn>(GetProcAddress(ntdll, "NtSuspendProcess"));
}

ResponseAction ProcessSuspendResponder::Handle(const EnrichedFinding& alert) {
    ResponseAction ra;
    ra.action = Name();
    ra.target = std::to_wstring(alert.evidence.proc.pid);

    DWORD pid = alert.evidence.proc.pid;
    if (pid == 0) {
        ra.success = false;
        ra.message = L"no pid in evidence";
        return ra;
    }

    HANDLE h = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!h) {
        ra.success = false;
        ra.message = L"OpenProcess(PROCESS_SUSPEND_RESUME) failed";
        return ra;
    }

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
    ra.message = ra.success ? L"process suspended" : L"NtSuspendProcess failed";
    return ra;
}

} // namespace miniedr

#endif
