#include "output/central_sink.h"

#include <sstream>
#include <unordered_map>

namespace miniedr {

namespace {

static std::string FieldsToJson(const std::unordered_map<std::wstring, std::wstring>& fields) {
    std::ostringstream oss;
    oss << "{";
    bool first = true;
    for (const auto& kv : fields) {
        if (!first) oss << ",";
        first = false;
        auto k = JsonlFileSink::JsonEscape(JsonlFileSink::NarrowUtf8(kv.first));
        auto v = JsonlFileSink::JsonEscape(JsonlFileSink::NarrowUtf8(kv.second));
        oss << "\"" << k << "\":\"" << v << "\"";
    }
    oss << "}";
    return oss.str();
}

static std::string BuildEcsJson(const CanonicalEvent& ev) {
    std::ostringstream oss;
    auto image = JsonlFileSink::JsonEscape(JsonlFileSink::NarrowUtf8(ev.proc.image));
    auto cmd = JsonlFileSink::JsonEscape(JsonlFileSink::NarrowUtf8(ev.proc.command_line));
    auto user = JsonlFileSink::JsonEscape(JsonlFileSink::NarrowUtf8(ev.proc.user));
    auto source = JsonlFileSink::JsonEscape(JsonlFileSink::NarrowUtf8(ev.source));

    auto dst_ip_it = ev.fields.find(L"DestinationIp");
    auto src_ip_it = ev.fields.find(L"SourceIp");
    auto dst_ip = dst_ip_it == ev.fields.end() ? "" : JsonlFileSink::JsonEscape(JsonlFileSink::NarrowUtf8(dst_ip_it->second));
    auto src_ip = src_ip_it == ev.fields.end() ? "" : JsonlFileSink::JsonEscape(JsonlFileSink::NarrowUtf8(src_ip_it->second));

    oss << "{"
        << "\"ecs_version\":\"1.12.0\","
        << "\"event\":{\"kind\":\"alert\",\"category\":[\"process\"],\"type\":[\"info\"],\"provider\":\"" << source << "\"},"
        << "\"process\":{\"pid\":" << ev.proc.pid << ",\"executable\":\"" << image << "\",\"command_line\":\"" << cmd << "\"},"
        << "\"user\":{\"name\":\"" << user << "\"},"
        << "\"source\":{\"ip\":\"" << src_ip << "\"},"
        << "\"destination\":{\"ip\":\"" << dst_ip << "\"}"
        << "}";
    return oss.str();
}

static std::string BuildOcsfJson(const Finding& f) {
    std::ostringstream oss;
    auto severity = JsonlFileSink::JsonEscape(JsonlFileSink::NarrowUtf8(f.severity));
    auto title = JsonlFileSink::JsonEscape(JsonlFileSink::NarrowUtf8(f.title));
    auto rule = JsonlFileSink::JsonEscape(JsonlFileSink::NarrowUtf8(f.rule_id));
    auto source = JsonlFileSink::JsonEscape(JsonlFileSink::NarrowUtf8(f.evidence.source));
    auto image = JsonlFileSink::JsonEscape(JsonlFileSink::NarrowUtf8(f.evidence.proc.image));
    auto cmd = JsonlFileSink::JsonEscape(JsonlFileSink::NarrowUtf8(f.evidence.proc.command_line));

    oss << "{"
        << "\"metadata\":{\"version\":\"1.0.0\"},"
        << "\"category_name\":\"Finding\","
        << "\"severity\":\"" << severity << "\","
        << "\"activity_name\":\"" << title << "\","
        << "\"type_name\":\"" << rule << "\","
        << "\"provider\":\"" << source << "\","
        << "\"process\":{\"pid\":" << f.evidence.proc.pid << ",\"path\":\"" << image << "\",\"cmd_line\":\"" << cmd << "\"}"
        << "}";
    return oss.str();
}

static std::string BuildAlertJson(const Finding& f) {
    std::ostringstream oss;
    auto sev = JsonlFileSink::JsonEscape(JsonlFileSink::NarrowUtf8(f.severity));
    auto title = JsonlFileSink::JsonEscape(JsonlFileSink::NarrowUtf8(f.title));
    auto rule = JsonlFileSink::JsonEscape(JsonlFileSink::NarrowUtf8(f.rule_id));
    auto time = JsonlFileSink::JsonEscape(JsonlFileSink::NarrowUtf8(f.evidence.timestamp_utc));
    auto source = JsonlFileSink::JsonEscape(JsonlFileSink::NarrowUtf8(f.evidence.source));
    auto img = JsonlFileSink::JsonEscape(JsonlFileSink::NarrowUtf8(f.evidence.proc.image));
    auto cmd = JsonlFileSink::JsonEscape(JsonlFileSink::NarrowUtf8(f.evidence.proc.command_line));
    auto timg = JsonlFileSink::JsonEscape(JsonlFileSink::NarrowUtf8(f.evidence.target.image));
    auto summary = JsonlFileSink::JsonEscape(JsonlFileSink::NarrowUtf8(f.summary));
    auto ecs = BuildEcsJson(f.evidence);
    auto ocsf = BuildOcsfJson(f);

    oss << "{"
        << "\"severity\":\"" << sev << "\","
        << "\"title\":\"" << title << "\","
        << "\"rule_id\":\"" << rule << "\","
        << "\"timestamp_utc\":\"" << time << "\","
        << "\"source\":\"" << source << "\","
        << "\"source_eid\":" << f.evidence.source_eid << ","
        << "\"actor_pid\":" << f.evidence.proc.pid << ","
        << "\"actor_image\":\"" << img << "\","
        << "\"actor_command_line\":\"" << cmd << "\","
        << "\"target_pid\":" << f.evidence.target.pid << ","
        << "\"target_image\":\"" << timg << "\","
        << "\"fields\":" << FieldsToJson(f.evidence.fields) << ","
        << "\"ecs\":" << ecs << ","
        << "\"ocsf\":" << ocsf << ","
        << "\"summary\":\"" << summary << "\""
        << "}";
    return oss.str();
}

} // namespace

CentralUploadSink::CentralUploadSink(CentralManager& manager) : manager_(manager) {}

void CentralUploadSink::Emit(const Finding& f) {
    manager_.UploadAlert(f, BuildAlertJson(f));
}

void CentralUploadSink::EmitEnriched(const EnrichedFinding& f) {
    Emit(static_cast<const Finding&>(f));
}

} // namespace miniedr
