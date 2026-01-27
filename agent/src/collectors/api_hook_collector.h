#pragma once
#include <functional>
#include <string>
#include <thread>
#include <atomic>

#include "pipeline/event_types.h"

namespace miniedr {

// Phase 6: user-mode API call telemetry via Detours-injected Hook DLL.
// The Hook DLL connects to a named pipe and emits JSON lines.
//
// Note: hooking is optional and disabled by default. Keep it research-only.
class ApiHookCollector {
public:
    using Callback = std::function<void(const CanonicalEvent&)>;

    ApiHookCollector();
    ~ApiHookCollector();

    bool Start(Callback cb);
    void Stop();

private:
#ifdef _WIN32
    void ThreadMain();
#endif

    Callback cb_;
    std::atomic<bool> running_{false};
    std::thread th_;
};

} // namespace miniedr
