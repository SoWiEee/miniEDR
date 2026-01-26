#pragma once
#ifdef _WIN32
#include <windows.h>
#include <functional>
#include <string>
#include <thread>
#include <atomic>
#include <vector>

#include "pipeline/event_types.h"
#include "../../../driver/include/miniedr_ioctl.h"

namespace miniedr {

class DriverCollector {
public:
    using Callback = std::function<void(const CanonicalEvent& ev)>;

    DriverCollector();
    ~DriverCollector();

    bool Start(Callback cb);
    void Stop();

private:
    HANDLE h_ = INVALID_HANDLE_VALUE;
    std::thread t_;
    std::atomic<bool> running_{false};
    Callback cb_;

    void ThreadLoop();
    void HandleEventBlob(const uint8_t* data, size_t len);
};

} // namespace miniedr
#endif
