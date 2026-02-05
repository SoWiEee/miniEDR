#pragma once
#include <string>

namespace miniedr {

struct CentralConfig {
    bool enable = false;
    bool upload_events = true;
    bool fetch_policy = true;
    bool fetch_rules = true;
    int poll_interval_sec = 60;

    std::wstring server_url;
    std::wstring api_key;
    std::wstring events_path = L"/api/v1/events";
    std::wstring policy_path = L"/api/v1/policy";
    std::wstring rules_path = L"/api/v1/rules";
};

CentralConfig LoadCentralConfig(const std::wstring& path);

} // namespace miniedr
