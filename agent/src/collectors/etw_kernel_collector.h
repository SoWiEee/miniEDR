#pragma once
#ifdef _WIN32

#include "pipeline/event_types.h"

#include <Windows.h>
#include <evntrace.h>

#include <functional>
#include <string>
#include <thread>

namespace miniedr {

// Minimal ETW consumer for the NT Kernel Logger session.
// Phase 2 use: augment Sysmon with kernel-level process/image telemetry.
// Note: This is intentionally starter-grade (educational), not production hardened.
class EtwKernelCollector {
public:
    using Callback = std::function<void(const CanonicalEvent& ev)>;

    EtwKernelCollector();
    ~EtwKernelCollector();

    bool Start(Callback cb);
    void Stop();

private:
    Callback cb_;
    std::thread worker_;

    void Run();

    void* session_handle_ = nullptr; // TRACEHANDLE
    void* trace_handle_ = nullptr;   // TRACEHANDLE

    bool started_session_ = false;
    bool stop_requested_ = false;

    static void WINAPI OnEventRecord(_EVENT_RECORD* record);
    void HandleRecord(_EVENT_RECORD* record);

    static std::wstring GetStringProp(_EVENT_RECORD* record, const wchar_t* name);
    static uint32_t GetUInt32Prop(_EVENT_RECORD* record, const wchar_t* name);
};

} // namespace miniedr

#endif // _WIN32
