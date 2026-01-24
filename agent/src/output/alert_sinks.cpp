#include "output/alert_sinks.h"

#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

namespace miniedr {

static std::wstring Safe(const std::wstring& s) { return s.empty() ? L"(n/a)" : s; }

static std::string WideToUtf8(const std::wstring& w) {
#ifdef _WIN32
    if (w.empty()) return {};
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), str.data(), size_needed, nullptr, nullptr);
    return str;
#else
    // Fallback: naive narrowing
    std::string out;
    out.reserve(w.size());
    for (auto c : w) out.push_back(static_cast<char>(c & 0xFF));
    return out;
#endif
}

void ConsoleSink::Emit(const Finding& f) {
    std::wcout << L"[ALERT] [" << f.severity << L"] " << f.title << L"\n"
               << L"  Rule: " << f.rule_id << L"\n"
               << L"  Source: " << Safe(f.evidence.source) << L" (eid/opcode=" << f.evidence.source_eid << L")\n"
               << L"  Time: " << Safe(f.evidence.timestamp_utc) << L"\n"
               << L"  Actor PID : " << f.evidence.proc.pid << L"\n"
               << L"  Actor Image: " << Safe(f.evidence.proc.image) << L"\n"
               << L"  Actor Cmd  : " << Safe(f.evidence.proc.command_line) << L"\n";

    if (f.evidence.target.pid != 0 || !f.evidence.target.image.empty()) {
        std::wcout << L"  Target PID : " << f.evidence.target.pid << L"\n"
                   << L"  Target Image: " << Safe(f.evidence.target.image) << L"\n";
    }

    if (!f.evidence.fields.empty()) {
        std::wcout << L"  Fields:\n";
        int n = 0;
        for (const auto& kv : f.evidence.fields) {
            if (n++ >= 8) { std::wcout << L"    ...\n"; break; }
            std::wcout << L"    " << kv.first << L": " << Safe(kv.second) << L"\n";
        }
    }

    std::wcout << L"  Summary: " << f.summary << L"\n\n";
}

void ConsoleSink::EmitEnriched(const EnrichedFinding& f) {
    Emit(static_cast<const Finding&>(f));
    if (!f.scans.empty()) {
        std::wcout << L"  On-demand scans:\n";
        for (const auto& s : f.scans) {
            std::wcout << L"    - " << s.scanner
                       << L": executed=" << (s.executed ? L"true" : L"false")
                       << L", suspicious=" << (s.suspicious ? L"true" : L"false")
                       << L", exit_code=" << s.exit_code << L"\n"
                       << L"      out_dir=" << (s.output_dir.empty() ? L"(n/a)" : s.output_dir) << L"\n"
                       << L"      report=" << (s.raw_report_path.empty() ? L"(n/a)" : s.raw_report_path) << L"\n"
                       << L"      summary=" << (s.summary.empty() ? L"(n/a)" : s.summary) << L"\n";
        }
        std::wcout << L"\n";
    }
}


std::string JsonlFileSink::NarrowUtf8(const std::wstring& ws) {
    return WideToUtf8(ws);
}

std::string JsonlFileSink::JsonEscape(const std::string& s) {
    std::ostringstream oss;
    for (char c : s) {
        switch (c) {
        case '\\': oss << "\\\\"; break;
        case '"':  oss << "\\\""; break;
        case '\b': oss << "\\b"; break;
        case '\f': oss << "\\f"; break;
        case '\n': oss << "\\n"; break;
        case '\r': oss << "\\r"; break;
        case '\t': oss << "\\t"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                oss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)(unsigned char)c;
            } else {
                oss << c;
            }
        }
    }
    return oss.str();
}

JsonlFileSink::JsonlFileSink(const std::wstring& path) : path_(path) {}

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

void JsonlFileSink::Emit(const Finding& f) {
    std::ofstream ofs(NarrowUtf8(path_), std::ios::app);
    if (!ofs) return;

    auto sev = JsonEscape(NarrowUtf8(f.severity));
    auto title = JsonEscape(NarrowUtf8(f.title));
    auto rule = JsonEscape(NarrowUtf8(f.rule_id));
    auto time = JsonEscape(NarrowUtf8(f.evidence.timestamp_utc));
    auto source = JsonEscape(NarrowUtf8(f.evidence.source));
    auto img = JsonEscape(NarrowUtf8(f.evidence.proc.image));
    auto cmd = JsonEscape(NarrowUtf8(f.evidence.proc.command_line));
    auto timg = JsonEscape(NarrowUtf8(f.evidence.target.image));
    auto summary = JsonEscape(NarrowUtf8(f.summary));

    ofs << "{"
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
        << "\"summary\":\"" << summary << "\""
        << "}\n";
}

void JsonlFileSink::EmitEnriched(const EnrichedFinding& f) {
    std::ofstream ofs(NarrowUtf8(path_), std::ios::app);
    if (!ofs) return;

    auto sev = JsonEscape(NarrowUtf8(f.severity));
    auto title = JsonEscape(NarrowUtf8(f.title));
    auto rule = JsonEscape(NarrowUtf8(f.rule_id));
    auto time = JsonEscape(NarrowUtf8(f.evidence.timestamp_utc));
    auto img = JsonEscape(NarrowUtf8(f.evidence.proc.image));
    auto cmd = JsonEscape(NarrowUtf8(f.evidence.proc.command_line));
    auto summary = JsonEscape(NarrowUtf8(f.summary));

    ofs << "{"
        << "\"severity\":\"" << sev << "\","
        << "\"title\":\"" << title << "\","
        << "\"rule_id\":\"" << rule << "\","
        << "\"timestamp_utc\":\"" << time << "\","
        << "\"pid\":" << f.evidence.proc.pid << ","
        << "\"image\":\"" << img << "\","
        << "\"command_line\":\"" << cmd << "\","
        << "\"summary\":\"" << summary << "\","
        << "\"scans\":[";

    for (size_t i = 0; i < f.scans.size(); ++i) {
        const auto& s = f.scans[i];
        auto scanner = JsonEscape(NarrowUtf8(s.scanner));
        auto outdir = JsonEscape(NarrowUtf8(s.output_dir));
        auto report = JsonEscape(NarrowUtf8(s.raw_report_path));
        auto ssum = JsonEscape(NarrowUtf8(s.summary));

        ofs << "{"
            << "\"scanner\":\"" << scanner << "\","
            << "\"executed\":" << (s.executed ? "true" : "false") << ","
            << "\"suspicious\":" << (s.suspicious ? "true" : "false") << ","
            << "\"exit_code\":" << s.exit_code << ","
            << "\"output_dir\":\"" << outdir << "\","
            << "\"report_path\":\"" << report << "\","
            << "\"summary\":\"" << ssum << "\""
            << "}";
        if (i + 1 < f.scans.size()) ofs << ",";
    }
    ofs << "]}\n";
}

} // namespace miniedr
