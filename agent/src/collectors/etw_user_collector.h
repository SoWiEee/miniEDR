#pragma once
#ifdef _WIN32

#include "pipeline/event_types.h"

#include <Windows.h>

#include <krabs/krabs.hpp>

#include <functional>
#include <memory>
#include <string>
#include <thread>

namespace miniedr {

// User-mode ETW consumer for script/AMSI/memory signals.
// Uses named ETW providers to capture PowerShell/AMSI and memory-related events.
class EtwUserCollector {
public:
    using Callback = std::function<void(const CanonicalEvent& ev)>;

    EtwUserCollector();
    ~EtwUserCollector();

    bool Start(Callback cb);
    void Stop();

private:
    Callback cb_;
    std::thread worker_;

    void Run();

    std::unique_ptr<krabs::user_trace> trace_;
    bool stop_requested_ = false;
};

} // namespace miniedr

#endif // _WIN32
