#pragma once
#include "scanners/scanner_iface.h"
#include <string>

namespace miniedr {

class PeSieveAdapter : public IOnDemandScanner {
public:
    explicit PeSieveAdapter(std::wstring exe_path);
    std::wstring Name() const override { return L"pe-sieve"; }
    ScannerResult Scan(uint32_t pid, const std::wstring& out_dir_root) override;

private:
    std::wstring exe_path_;
};

} // namespace miniedr
