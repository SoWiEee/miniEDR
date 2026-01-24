#pragma once
#include "pipeline/event_types.h"
#include <optional>
#include <string>
#include <vector>

namespace miniedr {

// Rule engine in Phase 1 is intentionally small and readable.
// We focus on Sysmon EID 1 (ProcessCreate) and implement "suspicious child process" rules.
//
// You can expand this into a data-driven YAML/JSON ruleset in Phase 2.
//
struct ProcessCreateRule {
    std::wstring id;
    std::wstring title;
    std::wstring severity;
    std::vector<std::wstring> parent_image_contains; // any match
    std::vector<std::wstring> child_image_contains;  // any match
    std::vector<std::wstring> cmdline_contains;      // any match (optional)
    std::wstring summary_template;
};

class RuleEngine {
public:
    RuleEngine();

    // Returns all findings for the event (often 0 or 1 in Phase 1).
    std::vector<Finding> Evaluate(const CanonicalEvent& ev) const;

private:
    std::vector<ProcessCreateRule> proc_create_rules_;
    static bool ContainsI(const std::wstring& haystack, const std::wstring& needle);
};

} // namespace miniedr
