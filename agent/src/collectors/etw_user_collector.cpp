#include "collectors/etw_user_collector.h"

#ifdef _WIN32

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cwctype>
#include <optional>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

namespace miniedr {

namespace {

using json = nlohmann::json;

constexpr const wchar_t* kPowerShellProvider = L"Microsoft-Windows-PowerShell";
constexpr const wchar_t* kAmsiProvider = L"Microsoft-Windows-Antimalware-Scan-Interface";
constexpr const wchar_t* kMemoryProvider = L"Microsoft-Windows-Kernel-Memory";
constexpr const wchar_t* kThreatIntelProvider = L"Microsoft-Windows-Threat-Intelligence";
constexpr const wchar_t* kKernelRegistryProvider = L"Microsoft-Windows-Kernel-Registry";

std::wstring ToWString(const std::string& input) {
    return std::wstring(input.begin(), input.end());
}

bool ContainsCaseInsensitive(const std::wstring& haystack, const std::wstring& needle) {
    if (needle.empty()) return true;
    auto it = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(),
                          [](wchar_t a, wchar_t b) {
                              return std::towlower(a) == std::towlower(b);
                          });
    return it != haystack.end();
}

template <typename T>
std::optional<T> TryParse(krabs::parser& parser, const std::wstring& name) {
    try {
        return parser.parse<T>(name);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

void AddEtwMetadata(json& payload, const krabs::schema& schema, const EVENT_RECORD& record) {
    payload["event_id"] = record.EventHeader.EventDescriptor.Id;
    payload["opcode"] = record.EventHeader.EventDescriptor.Opcode;
    payload["task"] = record.EventHeader.EventDescriptor.Task;
    payload["provider"] = std::wstring(schema.provider_name());
    payload["event_name"] = std::wstring(schema.event_name());
}

void EmitJsonPayload(CanonicalEvent& ev, const krabs::schema& schema, const EVENT_RECORD& record) {
    json payload;
    AddEtwMetadata(payload, schema, record);
    ev.fields[L"EtwPayloadJson"] = ToWString(payload.dump());
}

} // namespace

EtwUserCollector::EtwUserCollector() = default;

EtwUserCollector::~EtwUserCollector() {
    Stop();
}

bool EtwUserCollector::Start(Callback cb) {
    cb_ = std::move(cb);
    stop_requested_ = false;

    worker_ = std::thread([this]() { Run(); });
    return true;
}

void EtwUserCollector::Stop() {
    stop_requested_ = true;

    if (trace_) {
        trace_->stop();
    }

    if (worker_.joinable()) worker_.join();

    trace_.reset();
}

void EtwUserCollector::Run() {
    trace_ = std::make_unique<krabs::user_trace>();

    krabs::provider<> powershell_provider(kPowerShellProvider);
    powershell_provider.add_on_event_callback([this](const EVENT_RECORD& record, const krabs::trace_context& context) {
        if (stop_requested_ || !cb_) return;

        krabs::schema schema(record, context.schema_locator);
        const std::wstring event_name = std::wstring(schema.event_name());
        if (!ContainsCaseInsensitive(event_name, L"script")) return;

        krabs::parser parser(schema);

        CanonicalEvent ev;
        ev.type = EventType::ScriptBlock;
        ev.source = L"etw";
        ev.source_eid = record.EventHeader.EventDescriptor.Id;

        if (auto pid = TryParse<uint32_t>(parser, L"ProcessId")) {
            ev.proc.pid = *pid;
        }
        if (auto user = TryParse<std::wstring>(parser, L"User")) {
            ev.proc.user = *user;
        }
        if (auto script_text = TryParse<std::wstring>(parser, L"ScriptBlockText")) {
            ev.fields[L"ScriptBlockText"] = *script_text;
        } else if (auto script_text_alt = TryParse<std::wstring>(parser, L"ScriptText")) {
            ev.fields[L"ScriptBlockText"] = *script_text_alt;
        }
        if (auto script_id = TryParse<std::wstring>(parser, L"ScriptBlockId")) {
            ev.fields[L"ScriptBlockId"] = *script_id;
        }
        if (auto path = TryParse<std::wstring>(parser, L"Path")) {
            ev.fields[L"ScriptPath"] = *path;
        }

        EmitJsonPayload(ev, schema, record);

        cb_(ev);
    });

    krabs::provider<> amsi_provider(kAmsiProvider);
    amsi_provider.add_on_event_callback([this](const EVENT_RECORD& record, const krabs::trace_context& context) {
        if (stop_requested_ || !cb_) return;

        krabs::schema schema(record, context.schema_locator);
        krabs::parser parser(schema);

        CanonicalEvent ev;
        ev.type = EventType::AmsiScan;
        ev.source = L"etw";
        ev.source_eid = record.EventHeader.EventDescriptor.Id;

        if (auto pid = TryParse<uint32_t>(parser, L"ProcessId")) {
            ev.proc.pid = *pid;
        }
        if (auto app = TryParse<std::wstring>(parser, L"AppName")) {
            ev.fields[L"AppName"] = *app;
        }
        if (auto content = TryParse<std::wstring>(parser, L"Content")) {
            ev.fields[L"Content"] = *content;
        }
        if (auto content_name = TryParse<std::wstring>(parser, L"ContentName")) {
            ev.fields[L"ContentName"] = *content_name;
        }
        if (auto result = TryParse<uint32_t>(parser, L"ScanResult")) {
            ev.fields[L"ScanResult"] = std::to_wstring(*result);
        }

        EmitJsonPayload(ev, schema, record);

        cb_(ev);
    });

    krabs::provider<> memory_provider(kMemoryProvider);
    memory_provider.add_on_event_callback([this](const EVENT_RECORD& record, const krabs::trace_context& context) {
        if (stop_requested_ || !cb_) return;

        krabs::schema schema(record, context.schema_locator);
        krabs::parser parser(schema);

        CanonicalEvent ev;
        ev.type = EventType::MemoryOperation;
        ev.source = L"etw";
        ev.source_eid = record.EventHeader.EventDescriptor.Id;

        if (auto pid = TryParse<uint32_t>(parser, L"ProcessId")) {
            ev.proc.pid = *pid;
        }
        const std::wstring event_name = std::wstring(schema.event_name());
        if (!event_name.empty()) {
            ev.fields[L"Operation"] = event_name;
        }
        if (auto base = TryParse<uint64_t>(parser, L"BaseAddress")) {
            ev.fields[L"BaseAddress"] = std::to_wstring(*base);
        }
        if (auto size = TryParse<uint64_t>(parser, L"RegionSize")) {
            ev.fields[L"RegionSize"] = std::to_wstring(*size);
        }
        if (auto protect = TryParse<uint32_t>(parser, L"Protection")) {
            ev.fields[L"Protection"] = std::to_wstring(*protect);
        }

        EmitJsonPayload(ev, schema, record);

        cb_(ev);
    });

    krabs::provider<> threat_provider(kThreatIntelProvider);
    threat_provider.add_on_event_callback([this](const EVENT_RECORD& record, const krabs::trace_context& context) {
        if (stop_requested_ || !cb_) return;

        krabs::schema schema(record, context.schema_locator);
        krabs::parser parser(schema);

        CanonicalEvent ev;
        ev.type = EventType::ThreatIntel;
        ev.source = L"etw";
        ev.source_eid = record.EventHeader.EventDescriptor.Id;

        if (auto pid = TryParse<uint32_t>(parser, L"ProcessId")) {
            ev.proc.pid = *pid;
        }
        if (auto desc = TryParse<std::wstring>(parser, L"Description")) {
            ev.fields[L"Description"] = *desc;
        }
        if (auto name = TryParse<std::wstring>(parser, L"ThreatName")) {
            ev.fields[L"ThreatName"] = *name;
        }

        EmitJsonPayload(ev, schema, record);

        cb_(ev);
    });

    krabs::provider<> registry_provider(kKernelRegistryProvider);
    registry_provider.add_on_event_callback([this](const EVENT_RECORD& record, const krabs::trace_context& context) {
        if (stop_requested_ || !cb_) return;

        krabs::schema schema(record, context.schema_locator);
        krabs::parser parser(schema);

        CanonicalEvent ev;
        ev.type = EventType::RegistrySetValue;
        ev.source = L"etw";
        ev.source_eid = record.EventHeader.EventDescriptor.Id;

        if (auto pid = TryParse<uint32_t>(parser, L"ProcessId")) {
            ev.proc.pid = *pid;
        }
        if (auto key = TryParse<std::wstring>(parser, L"KeyName")) {
            ev.fields[L"RegistryKey"] = *key;
        }
        if (auto value = TryParse<std::wstring>(parser, L"ValueName")) {
            ev.fields[L"RegistryValueName"] = *value;
        }

        EmitJsonPayload(ev, schema, record);

        cb_(ev);
    });

    trace_->enable(powershell_provider);
    trace_->enable(amsi_provider);
    trace_->enable(memory_provider);
    trace_->enable(threat_provider);
    trace_->enable(registry_provider);

    trace_->start();
}

} // namespace miniedr

#endif // _WIN32
