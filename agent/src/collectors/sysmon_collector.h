#pragma once
#ifdef _WIN32

#include <windows.h>
#include <winevt.h>
#include <functional>
#include <string>

#pragma comment(lib, "wevtapi.lib")

namespace miniedr {

// Subscribes to "Microsoft-Windows-Sysmon/Operational" and emits (EID, XML) pairs.
class SysmonCollector {
public:
    using Callback = std::function<void(uint32_t eid, const std::wstring& xml)>;

    SysmonCollector();
    ~SysmonCollector();

    bool Start(Callback cb);
    void Stop();

private:
    EVT_HANDLE subscription_ = nullptr;
    Callback cb_;

    static DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action,
                                             PVOID user_context,
                                             EVT_HANDLE event);
    void OnEvent(EVT_HANDLE event);
    static std::wstring RenderEventXml(EVT_HANDLE event);
    static uint32_t ExtractEventIdFromXml(const std::wstring& xml);
};

} // namespace miniedr

#endif // _WIN32
