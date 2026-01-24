#include "scanners/yara/yara_adapter.h"
#include "scanners/process_runner.h"

#ifdef _WIN32
#include <filesystem>
#include <sstream>

namespace fs = std::filesystem;

namespace miniedr {

static bool FileExists(const fs::path& p) {
    std::error_code ec;
    return fs::exists(p, ec) && fs::is_regular_file(p, ec);
}

static bool PathExists(const fs::path& p) {
    std::error_code ec;
    return fs::exists(p, ec);
}

YaraAdapter::YaraAdapter(std::wstring yara_exe, std::wstring rules_path, bool recursive)
    : yara_exe_(std::move(yara_exe)), rules_path_(std::move(rules_path)), recursive_(recursive) {}

ScannerResult YaraAdapter::Scan(uint32_t pid, const std::wstring& out_dir_root) {
    ScannerResult r;
    r.scanner = Name();

    fs::path exe(yara_exe_);
    if (!FileExists(exe)) {
        r.summary = L"yara executable not found: " + yara_exe_;
        return r;
    }
    fs::path rules(rules_path_);
    if (!PathExists(rules)) {
        r.summary = L"yara rules path not found: " + rules_path_;
        return r;
    }

    std::error_code ec;
    fs::create_directories(fs::path(out_dir_root), ec);

    // YARA CLI supports scanning a running process by passing PID as the TARGET argument
    // (example: `yara -r rules.yar 1234`). We keep this simple and capture stdout.
    std::wstringstream cmd;
    cmd << L"\"" << exe.wstring() << L"\" ";
    if (recursive_) cmd << L"-r ";
    cmd << L"\"" << rules.wstring() << L"\" " << pid;

    auto rr = RunProcessCapture(cmd.str(), out_dir_root, 30'000);
    r.executed = rr.started;
    r.exit_code = rr.started ? (int)rr.exit_code : -1;
    r.output_dir = out_dir_root;

    // If stdout contains matches, consider suspicious.
    if (!rr.stdout_text.empty()) {
        r.suspicious = true;
        r.summary = L"yara matched rules on process memory. See stdout captured in logs (not yet persisted).";
    } else {
        r.suspicious = false;
        r.summary = L"yara completed with no matches.";
    }
    return r;
}

} // namespace miniedr
#endif
