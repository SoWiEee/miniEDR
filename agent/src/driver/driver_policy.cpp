#include "driver/driver_policy.h"
#ifdef _WIN32

#include <fstream>
#include <sstream>
#include <algorithm>
#include <winioctl.h>

#include "../../driver/include/miniedr_ioctl.h"

namespace miniedr {

static std::wstring ReadAll(const std::wstring& path) {
    std::ifstream ifs(path);
    if (!ifs) return L"";
    std::stringstream ss;
    ss << ifs.rdbuf();
    std::string s = ss.str();
    int wlen = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(wlen, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), wlen);
    return w;
}

static bool ContainsToken(const std::wstring& s, const std::wstring& tok) {
    return s.find(tok) != std::wstring::npos;
}

static std::vector<uint32_t> ParseIntArray(const std::wstring& s, const std::wstring& key) {
    // Minimal JSON-ish parser: find "key": [ ... ]
    std::vector<uint32_t> out;
    auto pos = s.find(L"\"" + key + L"\"");
    if (pos == std::wstring::npos) return out;
    pos = s.find(L"[", pos);
    if (pos == std::wstring::npos) return out;
    auto end = s.find(L"]", pos);
    if (end == std::wstring::npos) return out;
    auto body = s.substr(pos + 1, end - (pos + 1));
    std::wstring num;
    for (wchar_t c : body) {
        if (iswdigit(c)) num.push_back(c);
        else {
            if (!num.empty()) {
                try { out.push_back((uint32_t)std::stoul(num)); } catch (...) {}
                num.clear();
            }
        }
    }
    if (!num.empty()) {
        try { out.push_back((uint32_t)std::stoul(num)); } catch (...) {}
    }
    return out;
}

DriverPolicyConfig LoadDriverPolicyConfig(const std::wstring& path) {
    DriverPolicyConfig cfg;
    auto txt = ReadAll(path);
    if (txt.empty()) return cfg;

    // enable_enforcement: true/false
    bool strip = true;
    auto pos = txt.find(L"\"enable_enforcement\"");
    if (pos != std::wstring::npos) {
        auto tpos = txt.find(L"true", pos);
        auto fpos = txt.find(L"false", pos);
        if (tpos != std::wstring::npos && (fpos == std::wstring::npos || tpos < fpos)) cfg.enable_enforcement = true;
    }

    // strip_instead_of_deny: true/false
    pos = txt.find(L"\"strip_instead_of_deny\"");
    if (pos != std::wstring::npos) {
        auto tpos = txt.find(L"true", pos);
        auto fpos = txt.find(L"false", pos);
        if (fpos != std::wstring::npos && (tpos == std::wstring::npos || fpos < tpos)) strip = false;
        else if (tpos != std::wstring::npos) strip = true;
    }
    cfg.strip_instead_of_deny = strip;

    cfg.protected_pids = ParseIntArray(txt, L"protected_pids");
    cfg.allowed_pids = ParseIntArray(txt, L"allowed_pids");
    return cfg;
}

bool ApplyDriverPolicy(HANDLE hDevice, const DriverPolicyConfig& cfg) {
    if (hDevice == INVALID_HANDLE_VALUE) return false;

    // Build variable-length buffer
    uint32_t protN = (uint32_t)cfg.protected_pids.size();
    uint32_t allowN = (uint32_t)cfg.allowed_pids.size();

    size_t sz = sizeof(MINIEDR_POLICY_V2) + (protN + allowN) * sizeof(uint32_t);
    std::vector<uint8_t> buf(sz);
    auto* p = reinterpret_cast<MINIEDR_POLICY_V2*>(buf.data());
    p->Version = MINIEDR_IOCTL_VERSION;
    p->Flags = cfg.enable_enforcement ? MINIEDR_POLICY_FLAG_ENFORCE_PROTECT : 0;
    if (cfg.enable_enforcement && cfg.strip_instead_of_deny) p->Flags |= MINIEDR_POLICY_FLAG_STRIP_INSTEAD_OF_DENY;
    p->ProtectedPidCount = protN;
    p->AllowedPidCount = allowN;

    auto* arr = reinterpret_cast<uint32_t*>(buf.data() + sizeof(MINIEDR_POLICY_V2));
    for (uint32_t i = 0; i < protN; ++i) arr[i] = cfg.protected_pids[i];
    for (uint32_t i = 0; i < allowN; ++i) arr[protN + i] = cfg.allowed_pids[i];

    DWORD out = 0;
    BOOL ok = DeviceIoControl(hDevice, IOCTL_MINIEDR_SET_POLICY_V2,
                             buf.data(), (DWORD)buf.size(),
                             nullptr, 0, &out, nullptr);
    return ok ? true : false;
}

bool DriverAllowlistAdd(HANDLE hDevice, uint32_t pid) {
    DWORD out = 0;
    BOOL ok = DeviceIoControl(hDevice, IOCTL_MINIEDR_ALLOWLIST_ADD,
                             &pid, sizeof(pid),
                             nullptr, 0, &out, nullptr);
    return ok ? true : false;
}

bool DriverAllowlistRemove(HANDLE hDevice, uint32_t pid) {
    DWORD out = 0;
    BOOL ok = DeviceIoControl(hDevice, IOCTL_MINIEDR_ALLOWLIST_REMOVE,
                             &pid, sizeof(pid),
                             nullptr, 0, &out, nullptr);
    return ok ? true : false;
}

} // namespace miniedr
#endif
