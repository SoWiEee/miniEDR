#pragma once
#include "pipeline/event_types.h"
#include <string>
#include <vector>

namespace miniedr {

struct Condition {
    std::wstring field;   // e.g. "proc.image", "proc.command_line", "fields.GrantedAccess", "type"
    std::wstring op;      // "equals_any" | "contains_any" | "regex_any"
    std::vector<std::wstring> values;
};

struct Rule {
    std::wstring id;
    std::wstring title;
    std::wstring severity;
    std::wstring summary;
    std::vector<Condition> all; // AND across all conditions
};

class RuleEngine {
public:
    RuleEngine();

    // Returns all findings for the event.
    std::vector<Finding> Evaluate(const CanonicalEvent& ev) const;

    // For debugging: number of loaded rules.
    size_t RuleCount() const { return rules_.size(); }

private:
    std::vector<Rule> rules_;

    static std::wstring GetFieldValue(const CanonicalEvent& ev, const std::wstring& field);
    static bool MatchCondition(const CanonicalEvent& ev, const Condition& c);
    static bool ContainsI(const std::wstring& haystack, const std::wstring& needle);

    static std::vector<Rule> LoadRulesFromJsonFile(const std::wstring& path);
    static std::vector<Rule> BuiltinRules();
};

} // namespace miniedr
