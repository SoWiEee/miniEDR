#pragma once
#include "scanners/scanner_iface.h"
#include <string>
#include <vector>

namespace miniedr {

class YaraAdapter : public IOnDemandScanner {
public:
    YaraAdapter(std::wstring yara_exe, std::wstring rules_path, bool recursive);
    std::wstring Name() const override { return L"yara"; }
    ScannerResult Scan(uint32_t pid, const std::wstring& out_dir_root) override;

private:
    std::wstring yara_exe_;
    std::wstring rules_path_;
    bool recursive_ = true;
};

} // namespace miniedr
