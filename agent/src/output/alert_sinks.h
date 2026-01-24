#pragma once
#include "pipeline/event_types.h"
#include <memory>
#include <string>
#include <vector>

namespace miniedr {

class IAlertSink {
public:
    virtual ~IAlertSink() = default;
    virtual void Emit(const Finding& f) = 0;
};

class ConsoleSink : public IAlertSink {
public:
    void Emit(const Finding& f) override;
};

class JsonlFileSink : public IAlertSink {
public:
    explicit JsonlFileSink(const std::wstring& path);
    void Emit(const Finding& f) override;

private:
    std::wstring path_;
    static std::string NarrowUtf8(const std::wstring& ws);
    static std::string JsonEscape(const std::string& s);
};

} // namespace miniedr
