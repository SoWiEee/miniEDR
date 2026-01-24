#pragma once
#include "pipeline/event_types.h"
#include <string>

namespace miniedr {

class IOnDemandScanner {
public:
    virtual ~IOnDemandScanner() = default;
    virtual std::wstring Name() const = 0;
    virtual ScannerResult Scan(uint32_t pid, const std::wstring& out_dir_root) = 0;
};

} // namespace miniedr
