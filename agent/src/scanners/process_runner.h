#pragma once
#ifdef _WIN32
#include <windows.h>
#include <string>

namespace miniedr {

struct ProcessRunResult {
    bool started = false;
    DWORD exit_code = 0;
    std::wstring stdout_text;
    std::wstring stderr_text;
};

ProcessRunResult RunProcessCapture(const std::wstring& cmdline,
                                  const std::wstring& workdir,
                                  DWORD timeout_ms);

} // namespace miniedr
#endif
