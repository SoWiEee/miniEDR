#pragma once
#include "scanners/scanner_iface.h"
#include <string>

namespace miniedr {

class HollowsHunterAdapter : public IOnDemandScanner {
public:
    explicit HollowsHunterAdapter(std::wstring exe_path);
    std::wstring Name() const override { return L"hollows_hunter"; }
    ScannerResult Scan(uint32_t pid, const std::wstring& out_dir_root) override;

private:
    std::wstring exe_path_;
};

} // namespace miniedr
