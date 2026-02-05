#include "control/central_manager.h"
#include "utils/encoding.h"
#include "utils/mini_json.h"

#include <chrono>
#include <fstream>
#include <sstream>
#include <thread>

namespace miniedr {

namespace {

static std::string ReadAll(const std::wstring& path_w) {
#ifdef _WIN32
    std::ifstream f(path_w, std::ios::binary);
#else
    std::ifstream f(WideToUtf8(path_w), std::ios::binary);
#endif
    if (!f) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static bool WriteAll(const std::wstring& path_w, const std::string& data) {
#ifdef _WIN32
    std::ofstream f(path_w, std::ios::binary | std::ios::trunc);
#else
    std::ofstream f(WideToUtf8(path_w), std::ios::binary | std::ios::trunc);
#endif
    if (!f) return false;
    f.write(data.data(), static_cast<std::streamsize>(data.size()));
    return true;
}

static std::string GetStringUtf8(const json::Value& obj, const char* key) {
    if (auto* v = obj.get(key); v && v->is_string()) return v->as_string();
    return {};
}

static std::optional<bool> GetOptBool(const json::Value& obj, const char* key) {
    if (auto* v = obj.get(key); v && v->is_bool()) return v->as_bool();
    return std::nullopt;
}

static std::vector<std::wstring> GetStringArray(const json::Value& obj, const char* key) {
    std::vector<std::wstring> out;
    auto* v = obj.get(key);
    if (!v || !v->is_array()) return out;
    for (const auto& it : v->as_array()) {
        if (it.is_string()) out.push_back(Utf8ToWide(it.as_string()));
    }
    return out;
}

} // namespace

CentralManager::CentralManager(CentralConfig cfg) : cfg_(std::move(cfg)) {}

CentralManager::~CentralManager() {
    Stop();
}

bool CentralManager::Start() {
    if (!cfg_.enable) return false;
    stop_requested_ = false;
    worker_ = std::thread([this]() { Run(); });
    return true;
}

void CentralManager::Stop() {
    stop_requested_ = true;
    if (worker_.joinable()) worker_.join();
}

void CentralManager::UploadAlert(const Finding&, const std::string& payload) {
    if (!cfg_.enable || !cfg_.upload_events || cfg_.server_url.empty()) return;
    const auto url = cfg_.server_url + cfg_.events_path;
    http_.Post(url, cfg_.api_key, payload);
}

PolicyConfig CentralManager::LoadPolicyFromFile(const std::wstring& path) {
    PolicyConfig policy;
    auto s = ReadAll(path);
    if (s.empty()) return policy;
    json::Value doc;
    try {
        doc = json::parse(s);
    } catch (...) {
        return policy;
    }
    if (!doc.is_object()) return policy;
    policy.enable_response = GetOptBool(doc, "enable_response");
    policy.auto_terminate_on_critical = GetOptBool(doc, "auto_terminate_on_critical");
    policy.auto_suspend_on_high = GetOptBool(doc, "auto_suspend_on_high");
    policy.auto_quarantine_on_high = GetOptBool(doc, "auto_quarantine_on_high");
    policy.enable_tamper_protection = GetOptBool(doc, "enable_tamper_protection");
    policy.tamper_terminate_on_detect = GetOptBool(doc, "tamper_terminate_on_detect");
    policy.tamper_suspend_on_detect = GetOptBool(doc, "tamper_suspend_on_detect");
    policy.protected_process_names = GetStringArray(doc, "protected_process_names");
    return policy;
}

void CentralManager::ApplyPolicy(ResponseConfig& resp_cfg, const PolicyConfig& policy) {
    if (policy.enable_response) resp_cfg.enable_response = *policy.enable_response;
    if (policy.auto_terminate_on_critical) resp_cfg.auto_terminate_on_critical = *policy.auto_terminate_on_critical;
    if (policy.auto_suspend_on_high) resp_cfg.auto_suspend_on_high = *policy.auto_suspend_on_high;
    if (policy.auto_quarantine_on_high) resp_cfg.auto_quarantine_on_high = *policy.auto_quarantine_on_high;
    if (policy.enable_tamper_protection) resp_cfg.enable_tamper_protection = *policy.enable_tamper_protection;
    if (policy.tamper_terminate_on_detect) resp_cfg.tamper_terminate_on_detect = *policy.tamper_terminate_on_detect;
    if (policy.tamper_suspend_on_detect) resp_cfg.tamper_suspend_on_detect = *policy.tamper_suspend_on_detect;
    if (!policy.protected_process_names.empty()) resp_cfg.protected_process_names = policy.protected_process_names;
}

void CentralManager::Run() {
    while (!stop_requested_) {
        if (cfg_.fetch_policy) FetchPolicy();
        if (cfg_.fetch_rules) FetchRules();
        for (int i = 0; i < cfg_.poll_interval_sec && !stop_requested_; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

void CentralManager::FetchPolicy() {
    if (cfg_.server_url.empty()) return;
    const auto url = cfg_.server_url + cfg_.policy_path;
    auto resp = http_.Get(url, cfg_.api_key);
    if (!resp.ok || resp.body.empty()) return;
    WriteAll(L"agent\\config\\policy.json", resp.body);
}

void CentralManager::FetchRules() {
    if (cfg_.server_url.empty()) return;
    const auto url = cfg_.server_url + cfg_.rules_path;
    auto resp = http_.Get(url, cfg_.api_key);
    if (!resp.ok || resp.body.empty()) return;

    json::Value doc;
    try {
        doc = json::parse(resp.body);
    } catch (...) {
        return;
    }
    if (!doc.is_object()) return;
    auto version = GetStringUtf8(doc, "version");
    if (version.empty()) return;

    auto current = ReadAll(L"rules\\remote_rules.version");
    if (current == version) return;

    if (WriteAll(L"rules\\remote_rules.json", resp.body)) {
        WriteAll(L"rules\\remote_rules.version", version);
    }
}

} // namespace miniedr
