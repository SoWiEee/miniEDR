#include "utils/win_path.h"

#ifdef _WIN32
#include <windows.h>
#include <vector>
#endif

namespace miniedr {

std::wstring GetExecutableDirW() {
#ifdef _WIN32
    std::vector<wchar_t> buf(4096, 0);
    DWORD n = GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
    if (n == 0 || n >= buf.size()) return L"";
    std::wstring full(buf.data(), n);
    auto pos = full.find_last_of(L"\\/");

    if (pos == std::wstring::npos) return L"";
    return full.substr(0, pos);
#else
    return L"";
#endif
}

} // namespace miniedr
