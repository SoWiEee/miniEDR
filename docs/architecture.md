# Architecture (Phase 1)

Pipeline:
Sysmon (EvtSubscribe) -> XML -> Normalizer -> RuleEngine -> AlertSinks

Phase 1 design constraints:
- Prefer readability over completeness.
- Preserve raw evidence (event XML) to avoid losing context.
- Only implement ProcessCreate (Sysmon EID 1) rules end-to-end.

Phase 2+ will expand this into:
Collectors (Sysmon + ETW) -> CanonicalEvent -> Enrichment -> Correlation -> Scanners -> Response.
