#pragma once
#include "pipeline/event_types.h"
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace miniedr {

// Phase 2: a small stateful correlator that looks for multi-event patterns.
// Goal: show students how to build "EDR logic" beyond single-event rules.
class Correlator {
public:
    std::vector<Finding> Process(const CanonicalEvent& ev);

private:
    struct Key {
        uint32_t src = 0;
        uint32_t dst = 0;
        bool operator==(const Key& o) const { return src == o.src && dst == o.dst; }
    };
    struct KeyHash {
        size_t operator()(const Key& k) const noexcept {
            return (static_cast<size_t>(k.src) << 32) ^ static_cast<size_t>(k.dst);
        }
    };

    struct Recent {
        uint64_t seen_ms = 0;
        CanonicalEvent ev;
    };

    std::unordered_map<Key, Recent, KeyHash> recent_access_;
    static uint64_t NowMs();

    static bool IsHighRightsAccess(const std::wstring& granted_access);
};

} // namespace miniedr
