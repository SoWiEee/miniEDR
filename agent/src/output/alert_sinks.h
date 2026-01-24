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
    // Phase 3: emit findings enriched with on-demand scan results
    virtual void EmitEnriched(const EnrichedFinding& f) { Emit(static_cast<const Finding&>(f)); }
};

class ConsoleSink : public IAlertSink {
public:
    void Emit(const Finding& f) override;
    void EmitEnriched(const EnrichedFinding& f) override;
};

class JsonlFileSink : public IAlertSink {
public:
    explicit JsonlFileSink(const std::wstring& path);
    void Emit(const Finding& f) override;
    void EmitEnriched(const EnrichedFinding& f) override;

    // Helpers are public so other sinks/utilities can reuse them.
    static std::string NarrowUtf8(const std::wstring& ws);
    static std::string JsonEscape(const std::string& s);

private:
    std::wstring path_;
};

} // namespace miniedr
