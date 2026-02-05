#include "control/central_config.h"
#include "utils/encoding.h"
#include "utils/mini_json.h"

#include <fstream>
#include <sstream>

namespace miniedr {

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

static std::wstring GetString(const json::Value& obj, const char* key) {
    if (auto* v = obj.get(key); v && v->is_string()) {
        return Utf8ToWide(v->as_string());
    }
    return L"";
}

static bool GetBool(const json::Value& obj, const char* key, bool fallback) {
    if (auto* v = obj.get(key); v && v->is_bool()) return v->as_bool();
    return fallback;
}

static int GetInt(const json::Value& obj, const char* key, int fallback) {
    if (auto* v = obj.get(key); v && v->is_number()) return static_cast<int>(v->as_number());
    return fallback;
}

CentralConfig LoadCentralConfig(const std::wstring& path) {
    CentralConfig cfg;
    auto s = ReadAll(path);
    if (s.empty()) return cfg;

    json::Value doc;
    try {
        doc = json::parse(s);
    } catch (...) {
        return cfg;
    }
    if (!doc.is_object()) return cfg;

    cfg.enable = GetBool(doc, "enable", cfg.enable);
    cfg.upload_events = GetBool(doc, "upload_events", cfg.upload_events);
    cfg.fetch_policy = GetBool(doc, "fetch_policy", cfg.fetch_policy);
    cfg.fetch_rules = GetBool(doc, "fetch_rules", cfg.fetch_rules);
    cfg.poll_interval_sec = GetInt(doc, "poll_interval_sec", cfg.poll_interval_sec);
    cfg.server_url = GetString(doc, "server_url");
    cfg.api_key = GetString(doc, "api_key");
    cfg.events_path = GetString(doc, "events_path");
    if (cfg.events_path.empty()) cfg.events_path = L"/api/v1/events";
    cfg.policy_path = GetString(doc, "policy_path");
    if (cfg.policy_path.empty()) cfg.policy_path = L"/api/v1/policy";
    cfg.rules_path = GetString(doc, "rules_path");
    if (cfg.rules_path.empty()) cfg.rules_path = L"/api/v1/rules";

    return cfg;
}

} // namespace miniedr
