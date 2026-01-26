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
	bool strip_instead_of_deny = true;        // whether to strip access instead of deny
};

DriverPolicyConfig LoadDriverPolicyConfig(const std::wstring& path);

bool ApplyDriverPolicy(HANDLE hDevice, const DriverPolicyConfig& cfg);

bool DriverAllowlistAdd(HANDLE hDevice, uint32_t pid);
bool DriverAllowlistRemove(HANDLE hDevice, uint32_t pid);

} // namespace miniedr
#endif
