#pragma once
#include "pipeline/event_types.h"
#include "scanners/scanner_iface.h"
#include <memory>
#include <string>
#include <vector>

namespace miniedr {

struct ScannerConfig {
    bool enable_on_demand = true;
    std::wstring output_root = L"scan_outputs";
    bool scan_on_high = true;
    std::vector<std::wstring> scan_rule_ids;
    std::wstring pe_sieve_path;
    std::wstring hollows_hunter_path;
    std::wstring yara_path;
    std::wstring yara_rules;
    bool yara_recursive = true;
};

class ScannerManager {
public:
    explicit ScannerManager(ScannerConfig cfg);
    std::vector<ScannerResult> RunOnDemand(const Finding& f);

private:
    ScannerConfig cfg_;
    std::vector<std::unique_ptr<IOnDemandScanner>> scanners_;
    static bool SeverityAtLeastHigh(const std::wstring& sev);
};

ScannerConfig LoadScannerConfig(const std::wstring& path);

} // namespace miniedr
