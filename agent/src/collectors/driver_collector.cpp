#include "collectors/driver_collector.h"
#include "enrich/process_enricher.h"
#include "driver/driver_policy.h"
#ifdef _WIN32

#include <iostream>
#include <chrono>

namespace miniedr {

static std::wstring AnsiToWideTrunc(const uint8_t* s, size_t maxlen) {
    size_t n = 0;
    while (n < maxlen && s[n] != 0) n++;
    if (n == 0) return L"";
    int wlen = MultiByteToWideChar(CP_ACP, 0, (const char*)s, (int)n, nullptr, 0);
    std::wstring w(wlen, 0);
    MultiByteToWideChar(CP_ACP, 0, (const char*)s, (int)n, w.data(), wlen);
    return w;
}

DriverCollector::DriverCollector() = default;
DriverCollector::~DriverCollector() { Stop(); }

bool DriverCollector::Start(Callback cb) {
    cb_ = std::move(cb);

    h_ = CreateFileW(MINIEDR_DEVICE_DOS_NAME,
                     GENERIC_READ,
                     FILE_SHARE_READ | FILE_SHARE_WRITE,
                     nullptr,
                     OPEN_EXISTING,
                     FILE_ATTRIBUTE_NORMAL,
                     nullptr);

    if (h_ == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[DriverCollector] Failed to open " << MINIEDR_DEVICE_DOS_NAME
                   << L". Is the driver installed and running?\n";
        return false;
    }

    // Version check (optional)
    MINIEDR_VERSION_INFO vi{};
    DWORD ret = 0;
    if (DeviceIoControl(h_, IOCTL_MINIEDR_GET_VERSION, nullptr, 0, &vi, sizeof(vi), &ret, nullptr)) {
        std::wcout << L"[DriverCollector] Driver version: 0x" << std::hex << vi.Version << std::dec << L"\n";
    }

// Apply driver enforcement policy (optional). We always add this agent PID to protected_pids
// so that, when enabled, dangerous handle access to the agent can be denied in kernel.
auto pol = LoadDriverPolicyConfig(L"agent\\config\\driver_policy.json");
pol.protected_pids.push_back(GetCurrentProcessId());
// Allow this agent itself to access protected targets.
pol.allowed_pids.push_back(GetCurrentProcessId());

if (!ApplyDriverPolicy(h_, pol)) {
    std::wcout << L"[DriverCollector] Policy not applied (driver may not support v2 yet).\n";
} else {
    std::wcout << L"[DriverCollector] Policy applied. enforcement="
               << (pol.enable_enforcement ? L"true" : L"false") << L"\n";
}

    running_ = true;
    t_ = std::thread([this]{ ThreadLoop(); });
    return true;
}

void DriverCollector::Stop() {
    running_ = false;
    if (t_.joinable()) t_.join();
    if (h_ != INVALID_HANDLE_VALUE) {
        CloseHandle(h_);
        h_ = INVALID_HANDLE_VALUE;
    }
}

void DriverCollector::ThreadLoop() {
    std::vector<uint8_t> buf(64 * 1024);

    while (running_) {
        DWORD out = 0;
        BOOL ok = DeviceIoControl(h_, IOCTL_MINIEDR_GET_EVENTS,
                                 nullptr, 0,
                                 buf.data(), (DWORD)buf.size(),
                                 &out, nullptr);
        if (ok && out > 0) {
            HandleEventBlob(buf.data(), out);
        } else {
            // backoff
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    }
}

void DriverCollector::HandleEventBlob(const uint8_t* data, size_t len) {
    static const ProcessEnricher enricher;
    size_t off = 0;
    while (off + sizeof(MINIEDR_EVENT_HEADER) <= len) {
        auto* h = reinterpret_cast<const MINIEDR_EVENT_HEADER*>(data + off);
        if (h->Size < sizeof(MINIEDR_EVENT_HEADER) || off + h->Size > len) break;

        CanonicalEvent ev;
        ev.source = L"kmdf";
        ev.source_eid = (uint32_t)h->Type;
        ev.timestamp_utc = L""; // user-mode can convert QPC to wall time if desired

        if (h->Type == MiniEdrEvent_ProcessCreate || h->Type == MiniEdrEvent_ProcessExit) {
            auto* p = reinterpret_cast<const MINIEDR_EVT_PROCESS*>(data + off);
            ev.type = (h->Type == MiniEdrEvent_ProcessCreate) ? EventType::ProcessCreate : EventType::Unknown;
            ev.proc.pid = p->Pid;
            ev.proc.ppid = p->ParentPid;
            // image file name is short; store into image field as best-effort
            ev.proc.image = AnsiToWideTrunc(p->ImageFileName, sizeof(p->ImageFileName));
        } else if (h->Type == MiniEdrEvent_ImageLoad) {
            auto* im = reinterpret_cast<const MINIEDR_EVT_IMAGELOAD*>(data + off);
            ev.type = EventType::ImageLoad;
            ev.proc.pid = im->Pid;
            ev.proc.image = im->ImagePath; // using image field for loaded module path (Phase 4 will add dedicated fields map)
        } else if (h->Type == MiniEdrEvent_HandleAccess) {
            ev.type = EventType::ProcessAccess;
            auto* ha = reinterpret_cast<const MINIEDR_EVT_HANDLEACCESS*>(data + off);
            ev.proc.pid = ha->SourcePid;
            ev.target.pid = ha->TargetPid;
            ev.fields[L"GrantedAccess"] = std::to_wstring(ha->DesiredAccess);
            ev.fields[L"Operation"] = std::to_wstring(ha->Operation);
            ev.proc.ppid = 0;
        } else {
            // ignore unknown types
        }

        enricher.Enrich(ev);

        if (cb_) cb_(ev);
        off += h->Size;
    }
}

} // namespace miniedr
#endif
