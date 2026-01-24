# Phase 3: On-demand scanners

MiniEDR Phase 3 integrates external memory scanners as **adapters**. The intent is to stay maintainable and fast:
we do not continuously scan every process; instead, we scan only after a rule/correlation has fired.

## PE-sieve adapter

- Invoked per target PID using `/pid` (required).
- Output directory set via `/dir`.
- JSON verbosity set via `/jlvl`.
- MiniEDR reads `scan_report.json` from the output directory and flags suspicious if `modified.total > 0`.

## HollowsHunter adapter

- Targets a PID via `/pid` (HollowsHunter supports PID lists; MiniEDR calls it with a single PID).
- Uses `/dir` and `/uniqd` to avoid overwriting previous outputs.
- MiniEDR searches recursively for a JSON report in the output folder and applies the same heuristic.

## Operational notes

- Expect false positives: these tools detect anomalies, not definitive malware verdicts.
- Prefer “alert → on-demand scan → triage” rather than always-on scanning for stability and developer ergonomics.
