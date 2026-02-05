#include "response/file_quarantine_responder.h"
#ifdef _WIN32

#include <windows.h>

#include <iomanip>
#include <sstream>

namespace miniedr {

static std::wstring ExtractFilename(const std::wstring& path) {
    if (path.empty()) return L"";
    auto pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return path;
    return path.substr(pos + 1);
}

static std::wstring BuildQuarantinePath(const std::wstring& original) {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    std::wstringstream ss;
    ss << L"quarantine\\"
       << std::setfill(L'0')
       << st.wYear << L"_"
       << std::setw(2) << st.wMonth << L"_"
       << std::setw(2) << st.wDay << L"_"
       << std::setw(2) << st.wHour
       << std::setw(2) << st.wMinute
       << std::setw(2) << st.wSecond
       << L"_"
       << ExtractFilename(original);
    return ss.str();
}

ResponseAction FileQuarantineResponder::Handle(const EnrichedFinding& alert) {
    ResponseAction ra;
    ra.action = Name();

    std::wstring path;
    auto it = alert.evidence.fields.find(L"TargetFilename");
    if (it != alert.evidence.fields.end()) path = it->second;
    if (path.empty()) path = alert.evidence.proc.image;

    ra.target = path;
    if (path.empty()) {
        ra.success = false;
        ra.message = L"no file path in evidence";
        return ra;
    }

    CreateDirectoryW(L"quarantine", nullptr);
    auto dest = BuildQuarantinePath(path);

    if (!MoveFileExW(path.c_str(), dest.c_str(), MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING)) {
        ra.success = false;
        ra.message = L"MoveFileExW failed";
        return ra;
    }

    ra.success = true;
    ra.message = L"file quarantined";
    ra.target = dest;
    return ra;
}

} // namespace miniedr

#endif
