#pragma once
#include "control/central_config.h"
#include "control/central_http.h"
#include "pipeline/event_types.h"
#include "response/response_manager.h"

#include <atomic>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace miniedr {

struct PolicyConfig {
    std::optional<bool> enable_response;
    std::optional<bool> auto_terminate_on_critical;
    std::optional<bool> auto_suspend_on_high;
    std::optional<bool> auto_quarantine_on_high;
    std::optional<bool> enable_tamper_protection;
    std::optional<bool> tamper_terminate_on_detect;
    std::optional<bool> tamper_suspend_on_detect;
    std::vector<std::wstring> protected_process_names;
};

class CentralManager {
public:
    explicit CentralManager(CentralConfig cfg);
    ~CentralManager();

    bool Start();
    void Stop();

    void UploadAlert(const Finding& f, const std::string& payload);

    PolicyConfig LoadPolicyFromFile(const std::wstring& path);
    void ApplyPolicy(ResponseConfig& resp_cfg, const PolicyConfig& policy);

private:
    void Run();
    void FetchPolicy();
    void FetchRules();

    CentralConfig cfg_;
    CentralHttpClient http_;
    std::thread worker_;
    std::atomic<bool> stop_requested_{false};
};

} // namespace miniedr
