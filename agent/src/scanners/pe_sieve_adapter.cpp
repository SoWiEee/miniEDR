#include "scanners/pe_sieve_adapter.h"
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
    // Heuristic: scan_report.json has: "modified" : { "total" : N }
    std::wregex re(LR"("modified"\s*:\s*\{\s*"total"\s*:\s*(\d+))", std::regex_constants::icase);
    std::wsmatch m;
    if (std::regex_search(json, m, re) && m.size() >= 2) {
        try { return std::stoul(m[1].str()) > 0; } catch (...) {}
    }
    return false;
}

PeSieveAdapter::PeSieveAdapter(std::wstring exe_path) : exe_path_(std::move(exe_path)) {}

ScannerResult PeSieveAdapter::Scan(uint32_t pid, const std::wstring& out_dir_root) {
    ScannerResult r;
    r.scanner = Name();

    fs::path exe(exe_path_);
    if (!FileExists(exe)) {
        r.summary = L"pe-sieve executable not found: " + exe_path_;
        return r;
    }

    auto ts = (long long)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    fs::path out_dir = fs::path(out_dir_root) / (L"pe-sieve_pid_" + std::to_wstring(pid) + L"_" + std::to_wstring(ts));
    std::error_code ec;
    fs::create_directories(out_dir, ec);

    // Required: /pid. Output: /dir. JSON verbosity: /jlvl. (per PE-sieve wiki)
    std::wstringstream cmd;
    cmd << L"\"" << exe.wstring() << L"\""
        << L" /pid " << pid
        << L" /dir \"" << out_dir.wstring() << L"\""
        << L" /quiet"
        << L" /jlvl 2";

    auto rr = RunProcessCapture(cmd.str(), out_dir.wstring(), 30'000);
    r.executed = rr.started;
    r.exit_code = rr.started ? (int)rr.exit_code : -1;
    r.output_dir = out_dir.wstring();

    fs::path scan_report = out_dir / "scan_report.json";
    if (FileExists(scan_report)) {
        r.raw_report_path = scan_report.wstring();
        auto json = ReadFileUtf8OrAnsi(scan_report);
        r.suspicious = JsonLooksSuspicious(json);
        r.summary = r.suspicious
            ? L"pe-sieve reported anomalies (modified.total > 0). See scan_report.json."
            : L"pe-sieve completed. No anomalies detected by heuristic (modified.total == 0).";
    } else {
        r.summary = L"pe-sieve completed, but scan_report.json not found in output directory.";
    }

    return r;
}

} // namespace miniedr
#endif
