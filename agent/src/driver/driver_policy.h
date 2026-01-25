#pragma once
#ifdef _WIN32
#include <string>
#include <vector>
#include <windows.h>

namespace miniedr {

struct DriverPolicyConfig {
    bool enable_enforcement = false;          // enable deny behavior in Ob callback
    std::vector<uint32_t> protected_pids;     // targets to protect
    std::vector<uint32_t> allowed_pids;       // sources allowed to access protected targets
};

DriverPolicyConfig LoadDriverPolicyConfig(const std::wstring& path);

bool ApplyDriverPolicy(HANDLE hDevice, const DriverPolicyConfig& cfg);

} // namespace miniedr
#endif
