#include "scanners/process_runner.h"
#ifdef _WIN32
#include <vector>

namespace miniedr {

static std::wstring ReadAllFromHandle(HANDLE h) {
    std::wstring out;
    const DWORD buf_size = 4096;
    std::vector<char> buf(buf_size);
    DWORD read = 0;
    while (ReadFile(h, buf.data(), buf_size, &read, nullptr) && read > 0) {
        int wlen = MultiByteToWideChar(CP_UTF8, 0, buf.data(), (int)read, nullptr, 0);
        UINT cp = CP_UTF8;
        if (wlen <= 0) { cp = CP_ACP; wlen = MultiByteToWideChar(CP_ACP, 0, buf.data(), (int)read, nullptr, 0); }
        if (wlen > 0) {
            std::wstring tmp(wlen, 0);
            MultiByteToWideChar(cp, 0, buf.data(), (int)read, tmp.data(), wlen);
            out.append(tmp);
        }
    }
    return out;
}

ProcessRunResult RunProcessCapture(const std::wstring& cmdline,
                                  const std::wstring& workdir,
                                  DWORD timeout_ms) {
    ProcessRunResult rr;

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE out_read = nullptr, out_write = nullptr;
    HANDLE err_read = nullptr, err_write = nullptr;

    if (!CreatePipe(&out_read, &out_write, &sa, 0)) return rr;
    if (!SetHandleInformation(out_read, HANDLE_FLAG_INHERIT, 0)) return rr;

    if (!CreatePipe(&err_read, &err_write, &sa, 0)) return rr;
    if (!SetHandleInformation(err_read, HANDLE_FLAG_INHERIT, 0)) return rr;

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = out_write;
    si.hStdError  = err_write;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};
    std::wstring mutable_cmd = cmdline;

    BOOL ok = CreateProcessW(
        nullptr,
        mutable_cmd.data(),
        nullptr, nullptr,
        TRUE,
        CREATE_NO_WINDOW,
        nullptr,
        workdir.empty() ? nullptr : workdir.c_str(),
        &si, &pi
    );

    CloseHandle(out_write);
    CloseHandle(err_write);

    if (!ok) {
        CloseHandle(out_read);
        CloseHandle(err_read);
        return rr;
    }

    rr.started = true;

    DWORD wait = WaitForSingleObject(pi.hProcess, timeout_ms);
    if (wait == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 2000);
    }

    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    rr.exit_code = exit_code;

    rr.stdout_text = ReadAllFromHandle(out_read);
    rr.stderr_text = ReadAllFromHandle(err_read);

    CloseHandle(out_read);
    CloseHandle(err_read);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return rr;
}

} // namespace miniedr
#endif
