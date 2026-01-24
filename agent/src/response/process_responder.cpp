#include "response/process_responder.h"
#ifdef _WIN32
#include <windows.h>
#include <sstream>

namespace miniedr {

ResponseAction ProcessTerminateResponder::Handle(const EnrichedFinding& alert) {
    ResponseAction ra;
    ra.action = Name();
    ra.target = std::to_wstring(alert.evidence.proc.pid);

    DWORD pid = alert.evidence.proc.pid;
    if (pid == 0) {
        ra.success = false;
        ra.message = L"no pid in evidence";
        return ra;
    }

    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!h) {
        ra.success = false;
        ra.message = L"OpenProcess(PROCESS_TERMINATE) failed";
        return ra;
    }

    BOOL ok = TerminateProcess(h, 1);
    CloseHandle(h);

    ra.success = ok ? true : false;
    ra.message = ok ? L"process terminated" : L"TerminateProcess failed";
    return ra;
}

} // namespace miniedr
#endif
