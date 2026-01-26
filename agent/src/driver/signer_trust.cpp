#include "driver/signer_trust.h"
#ifdef _WIN32

#include <fstream>
#include <sstream>
#include <algorithm>
#include <windows.h>

namespace miniedr {

static std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c){ return (wchar_t)towlower(c); });
    return s;
}

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

static bool ParseBool(const std::wstring& txt, const std::wstring& key, bool defv) {
    auto pos = txt.find(L"\"" + key + L"\"");
    if (pos == std::wstring::npos) return defv;
    auto tpos = txt.find(L"true", pos);
    auto fpos = txt.find(L"false", pos);
    if (tpos != std::wstring::npos && (fpos == std::wstring::npos || tpos < fpos)) return true;
    if (fpos != std::wstring::npos && (tpos == std::wstring::npos || fpos < tpos)) return false;
    return defv;
}

static std::vector<std::wstring> ParseStrArray(const std::wstring& s, const std::wstring& key) {
    std::vector<std::wstring> out;
    auto pos = s.find(L"\"" + key + L"\"");
    if (pos == std::wstring::npos) return out;
    pos = s.find(L"[", pos);
    if (pos == std::wstring::npos) return out;
    auto end = s.find(L"]", pos);
    if (end == std::wstring::npos) return out;
    auto body = s.substr(pos + 1, end - (pos + 1));

    bool in = false;
    std::wstring cur;
    for (wchar_t c : body) {
        if (!in) {
            if (c == L'"') { in = true; cur.clear(); }
        } else {
            if (c == L'"') { in = false; if (!cur.empty()) out.push_back(cur); }
            else cur.push_back(c);
        }
    }
    return out;
}

SignerTrustConfig LoadSignerTrustConfig(const std::wstring& path) {
    SignerTrustConfig cfg;
    auto txt = ReadAll(path);
    if (txt.empty()) return cfg;

    cfg.allow_microsoft_signed = ParseBool(txt, L"allow_microsoft_signed", true);
    cfg.require_trusted_chain = ParseBool(txt, L"require_trusted_chain", true);
    cfg.allow_subject_contains = ParseStrArray(txt, L"allow_subject_contains");
    cfg.allow_issuer_contains = ParseStrArray(txt, L"allow_issuer_contains");
    return cfg;
}

static bool ContainsAny(const std::wstring& hay, const std::vector<std::wstring>& needles) {
    if (hay.empty()) return false;
    auto hl = ToLower(hay);
    for (const auto& n : needles) {
        auto nl = ToLower(n);
        if (!nl.empty() && hl.find(nl) != std::wstring::npos) return true;
    }
    return false;
}

bool IsSignerAllowed(const SignerTrustConfig& cfg,
                     bool signer_trusted,
                     bool signer_is_microsoft,
                     const std::wstring& signer_subject,
                     const std::wstring& signer_issuer) {
    if (cfg.require_trusted_chain && !signer_trusted) return false;
    if (cfg.allow_microsoft_signed && signer_is_microsoft && signer_trusted) return true;
    if (ContainsAny(signer_subject, cfg.allow_subject_contains)) return true;
    if (ContainsAny(signer_issuer, cfg.allow_issuer_contains)) return true;
    return false;
}

} // namespace miniedr
#endif
