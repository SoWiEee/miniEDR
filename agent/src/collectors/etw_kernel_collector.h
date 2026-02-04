#pragma once
#ifdef _WIN32

#include "pipeline/event_types.h"

#include <Windows.h>
#include <evntrace.h>

#include <krabs/krabs.hpp>

#include <functional>
#include <memory>
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

    std::unique_ptr<krabs::kernel::trace> trace_;
    bool stop_requested_ = false;
};

} // namespace miniedr

#endif // _WIN32
