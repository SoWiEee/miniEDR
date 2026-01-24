#include "scanners/hollows_hunter_adapter.h"
#include "scanners/process_runner.h"

#ifdef _WIN32
#include <filesystem>
#include <fstream>
#include <regex>

namespace fs = std::filesystem;

namespace miniedr {

static bool FileExists(const fs::path& p) {
    std::error_code ec;
    return fs::exists(p, ec) && fs::is_regular_file(p, ec);
}

static std::wstring ReadFileUtf8OrAnsi(const fs::path& p) {
    std::ifstream ifs(p, std::ios::binary);
    if (!ifs) return L"";
    std::string data((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    int wlen = MultiByteToWideChar(CP_UTF8, 0, data.data(), (int)data.size(), nullptr, 0);
    UINT cp = CP_UTF8;
    if (wlen <= 0) { cp = CP_ACP; wlen = MultiByteToWideChar(CP_ACP, 0, data.data(), (int)data.size(), nullptr, 0); }
    if (wlen <= 0) return L"";
    std::wstring out(wlen, 0);
    MultiByteToWideChar(cp, 0, data.data(), (int)data.size(), out.data(), wlen);
    return out;
}

static bool JsonLooksSuspicious(const std::wstring& json) {
    std::wregex re(LR"("modified"\s*:\s*\{\s*"total"\s*:\s*(\d+))", std::regex_constants::icase);
    std::wsmatch m;
    if (std::regex_search(json, m, re) && m.size() >= 2) {
        try { return std::stoul(m[1].str()) > 0; } catch (...) {}
    }
    return false;
}

static bool FindAnyReportJson(const fs::path& dir, fs::path& found) {
    std::error_code ec;
    if (!fs::exists(dir, ec)) return false;
    for (auto it = fs::recursive_directory_iterator(dir, ec); it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) break;
        if (!it->is_regular_file(ec)) continue;
        auto name = it->path().filename().wstring();
        if (_wcsicmp(name.c_str(), L"scan_report.json") == 0 || _wcsicmp(name.c_str(), L"report.json") == 0) {
            found = it->path();
            return true;
        }
    }
    return false;
}

HollowsHunterAdapter::HollowsHunterAdapter(std::wstring exe_path) : exe_path_(std::move(exe_path)) {}

ScannerResult HollowsHunterAdapter::Scan(uint32_t pid, const std::wstring& out_dir_root) {
    ScannerResult r;
    r.scanner = Name();

    fs::path exe(exe_path_);
    if (!FileExists(exe)) {
        r.summary = L"hollows_hunter executable not found: " + exe_path_;
        return r;
    }

    auto ts = (long long)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    fs::path out_dir = fs::path(out_dir_root) / (L"hollows_hunter_pid_" + std::to_wstring(pid) + L"_" + std::to_wstring(ts));
    std::error_code ec;
    fs::create_directories(out_dir, ec);

    // HollowsHunter supports selecting targets by /pid; output directory via /dir; unique output directory via /uniqd. (per wiki)
    std::wstringstream cmd;
    cmd << L"\"" << exe.wstring() << L"\""
        << L" /pid " << pid
        << L" /dir \"" << out_dir.wstring() << L"\""
        << L" /uniqd";

    auto rr = RunProcessCapture(cmd.str(), out_dir.wstring(), 45'000);
    r.executed = rr.started;
    r.exit_code = rr.started ? (int)rr.exit_code : -1;
    r.output_dir = out_dir.wstring();

    fs::path report;
    if (FindAnyReportJson(out_dir, report)) {
        r.raw_report_path = report.wstring();
        auto json = ReadFileUtf8OrAnsi(report);
        r.suspicious = JsonLooksSuspicious(json);
        r.summary = r.suspicious
            ? L"hollows_hunter reported anomalies (modified.total > 0). See JSON report."
            : L"hollows_hunter completed. No anomalies detected by heuristic (modified.total == 0).";
    } else {
        auto out = rr.stdout_text + L"\n" + rr.stderr_text;
        if (out.find(L"shellcode") != std::wstring::npos || out.find(L"hook") != std::wstring::npos ||
            out.find(L"patched") != std::wstring::npos || out.find(L"implanted") != std::wstring::npos) {
            r.suspicious = true;
            r.summary = L"hollows_hunter output suggests suspicious findings; JSON report not located.";
        } else {
            r.summary = L"hollows_hunter completed; JSON report not located.";
        }
    }

    return r;
}

} // namespace miniedr
#endif
