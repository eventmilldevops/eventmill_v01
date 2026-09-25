# Starter guide: threat modeling tools documented — 2026-09-25

`docs/guides/Event_Mill_Starter_Guide.md` supports the demo lab, which shows
two pillars: network_forensics and threat_modeling. The network forensics half
was complete. The threat modeling half had no examples for
`threat_report_analyzer`, and nothing on `adversary_path_projector` or
`attack_path_detection_designer`.

## What changed

- **§8 Threat Intelligence Ingestion.** Added `pillar threat_modeling` (the
  ingester belongs to log_analysis but declares threat_modeling in
  `also_useful_in`), a combined-flags example, how to read coverage, and the
  chain into the projector via `--intel_artifact_id`.
- **§9 Threat Report Summaries (new).** `list_reports`, `summarize` with
  `--max_word_count`, `--focus_areas`, `--ignore_caps`, and `search_reports`,
  plus what `analysis_status` means and where the summary goes next.
- **§11 Adversary Path Projection, Visualization, and Detection Design (new).**
  A step-by-step workflow table on the shipped Application B flow map and
  Scattered Spider, followed by a command table per tool. The former §10
  (Attack Path Visualization) is folded into it, with the projector-graph
  route, `--attack_type`, side-by-side comparison, and the warning that the
  ASCII "Unprotected stages" line is not a finding.
- **§12 Cross-Module Workflow.** Step 5 said `import_scenario` takes a seed
  "from threat_intel_ingester or adversary_path_projector". The ingester
  produces no scenario seed. A projection step now sits between the ingester
  and the import.
- Sections 12–14 renumbered to 13–15.

## Corrections to existing text

- The ingester's provider page limits read "anthropic/openai 100". The
  provider manifests say `anthropic` 250 and `openai` 600
  (`framework/llm/providers/*.json`, verified 2026-09-24). The guide now uses
  those. **The ingester's own README still says 100** and was not changed here.

## Flags over JSON

Every `run` example uses `--key value`. The one exception is the visualizer's
inline `stages`: it is an array of objects, and `_coerce_flag_value` in
`framework/cli/shell.py` refuses a flag for any array whose items are not
strings. The guide now says so rather than leaving the JSON unexplained.

## Verified

Argument names, enums and defaults were checked against each plugin's
`schemas/input.schema.json`. No commands were run against a live session.
