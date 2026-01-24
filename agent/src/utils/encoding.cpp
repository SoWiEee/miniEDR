#include "utils/encoding.h"

#ifdef _WIN32
#include <windows.h>
#endif

namespace miniedr {

std::wstring Utf8ToWide(const std::string& s) {
#ifdef _WIN32
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    if (len <= 0) return L"";
    std::wstring out(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), len);
    return out;
#else
    return std::wstring(s.begin(), s.end());
#endif
}

std::string WideToUtf8(const std::wstring& ws) {
#ifdef _WIN32
    if (ws.empty()) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, ws.data(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";
    std::string out(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.data(), (int)ws.size(), out.data(), len, nullptr, nullptr);
    return out;
#else
    return std::string(ws.begin(), ws.end());
#endif
}

} // namespace miniedr
