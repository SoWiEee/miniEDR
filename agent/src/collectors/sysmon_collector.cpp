#include "collectors/sysmon_collector.h"

#ifdef _WIN32

#include <iostream>
#include <vector>

namespace miniedr {

SysmonCollector::SysmonCollector() = default;

SysmonCollector::~SysmonCollector() {
    Stop();
}

bool SysmonCollector::Start(Callback cb) {
    cb_ = std::move(cb);

    // Query: all events. Phase 1 keeps it simple; filtering happens in the normalizer.
    LPCWSTR channel = L"Microsoft-Windows-Sysmon/Operational";
    LPCWSTR query = L"*";

    subscription_ = EvtSubscribe(
        nullptr,               // Session
        nullptr,               // Signal event (unused)
        channel,
        query,
        nullptr,               // Bookmark
        this,                  // Context passed to callback
        (EVT_SUBSCRIBE_CALLBACK)SysmonCollector::SubscriptionCallback,
        EvtSubscribeToFutureEvents
    );

    if (!subscription_) {
        auto err = GetLastError();
        std::wcerr << L"[SysmonCollector] EvtSubscribe failed. GetLastError=" << err
                   << L". Did you install Sysmon and run as Administrator?\n";
        return false;
    }

    std::wcout << L"[SysmonCollector] Subscribed to Sysmon Operational channel.\n";
    return true;
}

void SysmonCollector::Stop() {
    if (subscription_) {
        EvtClose(subscription_);
        subscription_ = nullptr;
    }
}

DWORD WINAPI SysmonCollector::SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action,
                                                   PVOID user_context,
                                                   EVT_HANDLE event) {
    auto self = reinterpret_cast<SysmonCollector*>(user_context);
    if (!self) return 0;

    if (action == EvtSubscribeActionDeliver) {
        self->OnEvent(event);
    }
    return 0;
}

void SysmonCollector::OnEvent(EVT_HANDLE event) {
    auto xml = RenderEventXml(event);
    if (xml.empty()) return;

    auto eid = ExtractEventIdFromXml(xml);
    if (cb_) cb_(eid, xml);
}

std::wstring SysmonCollector::RenderEventXml(EVT_HANDLE event) {
    DWORD buffer_size = 0;
    DWORD buffer_used = 0;
    DWORD prop_count = 0;

    // First call to get required buffer size
    if (!EvtRender(nullptr, event, EvtRenderEventXml, 0, nullptr, &buffer_used, &prop_count)) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            return L"";
        }
        buffer_size = buffer_used;
    }

    std::vector<wchar_t> buffer(buffer_size / sizeof(wchar_t) + 2, 0);
    if (!EvtRender(nullptr, event, EvtRenderEventXml,
                   (DWORD)(buffer.size() * sizeof(wchar_t)),
                   buffer.data(), &buffer_used, &prop_count)) {
        return L"";
    }

    return std::wstring(buffer.data());
}

uint32_t SysmonCollector::ExtractEventIdFromXml(const std::wstring& xml) {
    // Matches: <EventID>1</EventID>
    const std::wstring needle1 = L"<EventID>";
    const std::wstring needle2 = L"</EventID>";
    auto p1 = xml.find(needle1);
    if (p1 == std::wstring::npos) return 0;
    p1 += needle1.size();
    auto p2 = xml.find(needle2, p1);
    if (p2 == std::wstring::npos) return 0;
    auto s = xml.substr(p1, p2 - p1);
    try {
        return static_cast<uint32_t>(std::stoul(s));
    } catch (...) {
        return 0;
    }
}

} // namespace miniedr

#endif // _WIN32
