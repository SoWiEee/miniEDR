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

void ConsoleSink::Emit(const Finding& f) {
    std::wcout << L"[ALERT] [" << f.severity << L"] " << f.title << L"\n"
               << L"  Rule: " << f.rule_id << L"\n"
               << L"  Time: " << Safe(f.evidence.timestamp_utc) << L"\n"
               << L"  PID : " << f.evidence.proc.pid << L"\n"
               << L"  Image: " << Safe(f.evidence.proc.image) << L"\n"
               << L"  Cmd  : " << Safe(f.evidence.proc.command_line) << L"\n"
               << L"  Summary: " << f.summary << L"\n\n";
}

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

void JsonlFileSink::Emit(const Finding& f) {
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
        << "\"summary\":\"" << summary << "\""
        << "}\n";
}

} // namespace miniedr
