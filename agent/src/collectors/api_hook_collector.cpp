#include "collectors/api_hook_collector.h"

#ifdef _WIN32
#include <windows.h>
#include <chrono>
#include <iostream>
#include <string>
#include <vector>

#include "utils/mini_json.h"
#include "utils/encoding.h"

namespace miniedr {

static const wchar_t* kPipeName = L"\\\\.\\pipe\\MiniEDR.ApiHook";

ApiHookCollector::ApiHookCollector() = default;
ApiHookCollector::~ApiHookCollector() { Stop(); }

bool ApiHookCollector::Start(Callback cb) {
    if (running_) return true;
    cb_ = std::move(cb);
    running_ = true;
    th_ = std::thread([this] { ThreadMain(); });
    return true;
}

void ApiHookCollector::Stop() {
    if (!running_) return;
    running_ = false;

    // Wake thread if blocked in ConnectNamedPipe by connecting once.
    HANDLE h = CreateFileW(kPipeName, GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);

    if (th_.joinable()) th_.join();
}

static std::wstring GetStr(const json::Object& o, const char* k) {
    auto it = o.find(k);
    if (it == o.end() || !it->second.is_string()) return L"";
    return Utf8ToWide(it->second.as_string());
}

static uint32_t GetU32(const json::Object& o, const char* k) {
    auto it = o.find(k);
    if (it == o.end() || !it->second.is_number()) return 0;
    double d = it->second.as_number();
    if (d < 0) return 0;
    return static_cast<uint32_t>(d);
}

void ApiHookCollector::ThreadMain() {
    while (running_) {
        HANDLE pipe = CreateNamedPipeW(
            kPipeName,
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            64 * 1024,
            64 * 1024,
            0,
            nullptr);

        if (pipe == INVALID_HANDLE_VALUE) {
            std::wcerr << L"[ApiHookCollector] CreateNamedPipeW failed.\n";
            Sleep(1000);
            continue;
        }

        BOOL ok = ConnectNamedPipe(pipe, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!ok) {
            CloseHandle(pipe);
            continue;
        }

        std::string buf;
        buf.reserve(64 * 1024);
        std::vector<char> tmp(4096);

        while (running_) {
            DWORD read = 0;
            BOOL r = ReadFile(pipe, tmp.data(), (DWORD)tmp.size(), &read, nullptr);
            if (!r || read == 0) break;

            buf.append(tmp.data(), tmp.data() + read);

            // Process newline-delimited JSON
            size_t pos = 0;
            while (true) {
                auto nl = buf.find('\n', pos);
                if (nl == std::string::npos) {
                    buf.erase(0, pos);
                    break;
                }
                std::string line = buf.substr(pos, nl - pos);
                pos = nl + 1;
                if (line.empty()) continue;

                try {
                    auto v = json::parse(line);
                    if (!v.is_object()) continue;
                    const auto& o = v.as_object();

                    CanonicalEvent ev;
                    ev.type = EventType::ApiCall;
                    ev.proc.pid = GetU32(o, "pid");
                    ev.target.pid = GetU32(o, "target_pid");

                    ev.fields[L"api"] = GetStr(o, "api");
                    ev.fields[L"module"] = GetStr(o, "module");
                    ev.fields[L"tid"] = std::to_wstring(GetU32(o, "tid"));
                    ev.fields[L"result"] = GetStr(o, "result");
                    ev.fields[L"win32_error"] = std::to_wstring(GetU32(o, "err"));

                    // Optional numeric fields for correlation
                    auto da = GetU32(o, "desired_access");
                    if (da) ev.fields[L"desired_access"] = L"0x" + std::to_wstring(da);

                    auto sz = GetU32(o, "size");
                    if (sz) ev.fields[L"size"] = std::to_wstring(sz);

                    if (cb_) cb_(ev);
                } catch (...) {
                    // ignore malformed lines
                }
            }
        }

        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    }
}

} // namespace miniedr
#endif
