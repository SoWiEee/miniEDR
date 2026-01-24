#include "scanners/scanner_manager.h"
#include "scanners/pe_sieve_adapter.h"
#include "scanners/hollows_hunter_adapter.h"
#include "scanners/yara/yara_adapter.h"

#ifdef _WIN32
#include <windows.h>
#endif

#include <filesystem>
#include <fstream>
#include <regex>
#include <algorithm>

namespace fs = std::filesystem;

namespace miniedr {

static std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c){ return (wchar_t)towlower(c); });
    return s;
}

static bool ContainsI(const std::wstring& a, const std::wstring& b) {
    return ToLower(a).find(ToLower(b)) != std::wstring::npos;
}

bool ScannerManager::SeverityAtLeastHigh(const std::wstring& sev) {
    auto s = ToLower(sev);
    return (s == L"high" || s == L"critical");
}

ScannerManager::ScannerManager(ScannerConfig cfg) : cfg_(std::move(cfg)) {
    if (!cfg_.pe_sieve_path.empty()) {
        scanners_.push_back(std::make_unique<PeSieveAdapter>(cfg_.pe_sieve_path));
    }
    if (!cfg_.hollows_hunter_path.empty()) {
        scanners_.push_back(std::make_unique<HollowsHunterAdapter>(cfg_.hollows_hunter_path));
    }
    if (!cfg_.yara_path.empty() && !cfg_.yara_rules.empty()) {
        scanners_.push_back(std::make_unique<YaraAdapter>(cfg_.yara_path, cfg_.yara_rules, cfg_.yara_recursive));
    }
}

std::vector<ScannerResult> ScannerManager::RunOnDemand(const Finding& f) {
    std::vector<ScannerResult> out;
    if (!cfg_.enable_on_demand) return out;

    bool trigger = false;
    if (cfg_.scan_on_high && SeverityAtLeastHigh(f.severity)) trigger = true;

    for (const auto& rid : cfg_.scan_rule_ids) {
        if (!rid.empty() && ContainsI(f.rule_id, rid)) { trigger = true; break; }
    }

    if (!trigger) return out;
    if (scanners_.empty()) return out;
    if (f.evidence.proc.pid == 0) return out;

    std::error_code ec;
    fs::create_directories(fs::path(cfg_.output_root), ec);

    for (auto& s : scanners_) {
        out.push_back(s->Scan(f.evidence.proc.pid, cfg_.output_root));
    }
    return out;
}

/* Minimal JSON reader for a fixed config file (Phase 3).
   We intentionally avoid external JSON dependencies at this stage.
*/
static std::string ReadAllBytesUtf8Path(const std::wstring& path) {
#ifdef _WIN32
    int len = WideCharToMultiByte(CP_UTF8, 0, path.c_str(), (int)path.size(), nullptr, 0, nullptr, nullptr);
    std::string p(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, path.c_str(), (int)path.size(), p.data(), len, nullptr, nullptr);
    std::ifstream ifs(p, std::ios::binary);
#else
    std::ifstream ifs(std::string(path.begin(), path.end()), std::ios::binary);
#endif
    if (!ifs) return {};
    return std::string((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
}

static std::wstring Utf8ToWide(const std::string& s) {
#ifdef _WIN32
    int wlen = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(wlen, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), wlen);
    return w;
#else
    return std::wstring(s.begin(), s.end());
#endif
}

static std::wstring GetJsonString(const std::string& j, const std::string& key) {
    std::regex re("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
    std::smatch m;
    if (std::regex_search(j, m, re) && m.size() >= 2) {
        return Utf8ToWide(m[1].str());
    }
    return L"";
}

static bool GetJsonBool(const std::string& j, const std::string& key, bool defv) {
    std::regex re("\"" + key + "\"\\s*:\\s*(true|false)", std::regex_constants::icase);
    std::smatch m;
    if (std::regex_search(j, m, re) && m.size() >= 2) {
        auto v = m[1].str();
        std::transform(v.begin(), v.end(), v.begin(), ::tolower);
        return v == "true";
    }
    return defv;
}

static std::vector<std::wstring> GetJsonStringArray(const std::string& j, const std::string& key) {
    std::vector<std::wstring> out;
    std::regex re("\"" + key + "\"\\s*:\\s*\\[([\\s\\S]*?)\\]");
    std::smatch m;
    if (!std::regex_search(j, m, re) || m.size() < 2) return out;

    std::string body = m[1].str();
    std::regex re_item("\"([^\"]+)\"");
    auto it = std::sregex_iterator(body.begin(), body.end(), re_item);
    auto end = std::sregex_iterator();
    for (; it != end; ++it) out.push_back(Utf8ToWide((*it)[1].str()));
    return out;
}

ScannerConfig LoadScannerConfig(const std::wstring& path) {
    ScannerConfig cfg;
    auto j = ReadAllBytesUtf8Path(path);
    if (j.empty()) return cfg;

    cfg.enable_on_demand = GetJsonBool(j, "enable_on_demand", true);
    cfg.scan_on_high = GetJsonBool(j, "scan_on_high", true);

    cfg.output_root = GetJsonString(j, "output_root");
    if (cfg.output_root.empty()) cfg.output_root = L"scan_outputs";

    cfg.scan_rule_ids = GetJsonStringArray(j, "scan_rule_ids");
    cfg.pe_sieve_path = GetJsonString(j, "pe_sieve_path");
    cfg.hollows_hunter_path = GetJsonString(j, "hollows_hunter_path");
    cfg.yara_path = GetJsonString(j, "yara_path");
    cfg.yara_rules = GetJsonString(j, "yara_rules");
    cfg.yara_recursive = GetJsonBool(j, "yara_recursive", true);
    return cfg;
}

} // namespace miniedr
