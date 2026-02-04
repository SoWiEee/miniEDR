#include "collectors/etw_kernel_collector.h"

#ifdef _WIN32

#include <krabs/krabs.hpp>
#include <nlohmann/json.hpp>

#include <winsock2.h>
#include <algorithm>
#include <cwctype>
#include <optional>
#include <sstream>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "ws2_32.lib")

namespace miniedr {

namespace {

using json = nlohmann::json;

std::wstring ToWString(const std::string& input) {
    return std::wstring(input.begin(), input.end());
}

std::wstring Ipv4ToWString(uint32_t addr) {
    addr = ntohl(addr);
    std::wstringstream ss;
    ss << ((addr >> 24) & 0xFF) << L"."
       << ((addr >> 16) & 0xFF) << L"."
       << ((addr >> 8) & 0xFF) << L"."
       << (addr & 0xFF);
    return ss.str();
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
std::optional<T> TryParse(const krabs::parser& parser, const wchar_t* name) {
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
    payload["provider"] = ToWString(schema.provider_name());
    payload["event_name"] = ToWString(schema.event_name());
}

} // namespace

EtwKernelCollector::EtwKernelCollector() = default;

EtwKernelCollector::~EtwKernelCollector() {
    Stop();
}

bool EtwKernelCollector::Start(Callback cb) {
    cb_ = std::move(cb);
    stop_requested_ = false;

    worker_ = std::thread([this]() { Run(); });
    return true;
}

void EtwKernelCollector::Stop() {
    stop_requested_ = true;

    if (trace_) {
        trace_->stop();
    }

    if (worker_.joinable()) worker_.join();

    trace_.reset();
}

void EtwKernelCollector::Run() {
    trace_ = std::make_unique<krabs::kernel::trace>();

    krabs::kernel::process_provider process_provider;
    process_provider.add_on_event_callback([this](const EVENT_RECORD& record, const krabs::trace_context& context) {
        if (stop_requested_ || !cb_) return;

        if (record.EventHeader.EventDescriptor.Opcode != EVENT_TRACE_TYPE_START) return;

        krabs::schema schema(record, context.schema_locator);
        krabs::parser parser(schema);

        CanonicalEvent ev;
        ev.type = EventType::ProcessCreate;
        ev.source = L"etw";
        ev.source_eid = record.EventHeader.EventDescriptor.Opcode;

        if (auto pid = TryParse<uint32_t>(parser, L"ProcessId")) {
            ev.proc.pid = *pid;
        }
        if (auto ppid = TryParse<uint32_t>(parser, L"ParentId")) {
            ev.proc.ppid = *ppid;
        }
        if (auto image = TryParse<std::wstring>(parser, L"ImageFileName")) {
            ev.proc.image = *image;
        }
        if (auto cmd = TryParse<std::wstring>(parser, L"CommandLine")) {
            ev.proc.command_line = *cmd;
        }

        json payload;
        AddEtwMetadata(payload, schema, record);
        ev.fields[L"EtwPayloadJson"] = ToWString(payload.dump());

        cb_(ev);
    });

    krabs::kernel::image_load_provider image_provider;
    image_provider.add_on_event_callback([this](const EVENT_RECORD& record, const krabs::trace_context& context) {
        if (stop_requested_ || !cb_) return;

        krabs::schema schema(record, context.schema_locator);
        krabs::parser parser(schema);

        CanonicalEvent ev;
        ev.type = EventType::ImageLoad;
        ev.source = L"etw";
        ev.source_eid = record.EventHeader.EventDescriptor.Opcode;

        if (auto pid = TryParse<uint32_t>(parser, L"ProcessId")) {
            ev.proc.pid = *pid;
        }

        std::wstring image_loaded;
        if (auto image = TryParse<std::wstring>(parser, L"FileName")) {
            image_loaded = *image;
        } else if (auto image = TryParse<std::wstring>(parser, L"ImageFileName")) {
            image_loaded = *image;
        }
        if (!image_loaded.empty()) {
            ev.fields[L"ImageLoaded"] = image_loaded;
        }

        json payload;
        AddEtwMetadata(payload, schema, record);
        ev.fields[L"EtwPayloadJson"] = ToWString(payload.dump());

        cb_(ev);
    });

    krabs::kernel::network_tcpip_provider network_provider;
    network_provider.add_on_event_callback([this](const EVENT_RECORD& record, const krabs::trace_context& context) {
        if (stop_requested_ || !cb_) return;

        krabs::schema schema(record, context.schema_locator);
        const std::wstring event_name = ToWString(schema.event_name());
        if (!ContainsCaseInsensitive(event_name, L"connect")) return;

        krabs::parser parser(schema);

        CanonicalEvent ev;
        ev.type = EventType::NetworkConnect;
        ev.source = L"etw";
        ev.source_eid = record.EventHeader.EventDescriptor.Opcode;

        if (auto pid = TryParse<uint32_t>(parser, L"pid")) {
            ev.proc.pid = *pid;
        } else if (auto pid_alt = TryParse<uint32_t>(parser, L"ProcessId")) {
            ev.proc.pid = *pid_alt;
        }

        if (auto saddr = TryParse<uint32_t>(parser, L"saddr")) {
            ev.fields[L"SourceIp"] = Ipv4ToWString(*saddr);
        }
        if (auto daddr = TryParse<uint32_t>(parser, L"daddr")) {
            ev.fields[L"DestinationIp"] = Ipv4ToWString(*daddr);
        }
        if (auto sport = TryParse<uint16_t>(parser, L"sport")) {
            ev.fields[L"SourcePort"] = std::to_wstring(*sport);
        }
        if (auto dport = TryParse<uint16_t>(parser, L"dport")) {
            ev.fields[L"DestinationPort"] = std::to_wstring(*dport);
        }

        json payload;
        AddEtwMetadata(payload, schema, record);
        ev.fields[L"EtwPayloadJson"] = ToWString(payload.dump());

        cb_(ev);
    });

    trace_->enable(process_provider);
    trace_->enable(image_provider);
    trace_->enable(network_provider);

    trace_->start();
}

} // namespace miniedr

#endif // _WIN32
