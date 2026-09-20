# G1a and G1b: what could be observed, and the first detection drafts

**Date:** 2026-09-20
**Branch:** `llm_5`
**Scope:** code. New `telemetry.py`, `generation.py`,
`schemas/detection_draft.schema.json`, `tests/test_telemetry_join.py` (14),
`tests/test_generation.py` (17); `normalization.py`, `tool.py`,
`schemas/input.schema.json`, `manifest.json`; telemetry library to v0.2.0;
spec §4.4 gains two error codes.
**Status:** built, and run live on `gcp_gemini` — which found two defects, one
a crash and one silent. Both fixed here. Suite **1705 → 1749**.

## G1a — the telemetry join

Every node now carries `telemetry_candidates[]`, `telemetry_readiness`,
`telemetry_notes`, `telemetry_library_version` and `observation_medium`.

Readiness across the four fixture pairs with their maps was **38
`stream_available`, 2 `periodic_only`, 3 `none_declared`** — corrected to
38 / 0 / 5 by the contamination fix below, which is where those numbers are
explained. Without a map every node is `none_declared`, because the library
joins on the component.

A component that declares no technologies produces no telemetry and also
grades `component_bound_partial`. That correspondence is the point: a map that
does not say what a component runs cannot produce product-specific telemetry,
and the pack now says so twice, in two independent fields.

**Readiness is a separate axis from `context_completeness`,** and a test
asserts that at least one grade carries more than one readiness. Folding them
into one word would repeat the `uncovered_mitigations` misreading.

**The physical rule.** A hop whose protocol is `physical` draws physical
sources — badge events, the door contact alarm, CCTV, the variance-management
audits — and **not** the network sources its technologies would otherwise
match. A wall port's technology is `ethernet-wall-port`, and offering a packet
capture for a person in a corridor is worse than offering nothing. It keys on
the reserved spelling registered in `docs/specs/reserved_vocabulary.md` §1.

**Seed gaps the join exposed.** Seven components matched nothing:
`web_console` (nodejs/react), `claims_api` (python/fastapi), `partner_api`
(go/grpc), `front_door` (azure front door/WAF), `blob_storage`
(azure_storage), plus the two technology-less ones. Two library entries were
added — `application.runtime_log` and `edge.waf_decision` — and
`object_store.access` extended to `azure_storage`. Library **v0.2.0, 36
sources**. Finding the gap by joining rather than by reading the list is
exactly what the fixtures are for.

## G1b — generation

`generate_detections` is implemented and no longer a planned action. One
heavy-tier call per batch, batched by path, with the whole path's outline
carried in every batch so a split never costs predecessor context.

**What the prompt withholds.** `provenance_by_field` never reaches a model —
it is 58% of the pack and nothing to reason about — and neither does
`uncovered_mitigations`, per §1.4b: generation sees `mitigation_focus` and the
ratio. Tests assert both absences.

**What validation refuses,** rather than trusting the model:

- a telemetry source that was **not offered** for that node;
- any `DS####` identifier anywhere in the draft;
- `missing_data_behaviour` other than `insufficient_telemetry` — absent data
  may never evaluate as benign;
- `logsource.product` at any grade below `component_bound`;
- a changed `technique_id`, a mismatched `draft_id`, a title that does not
  begin with the technique;
- a native event id claimed with no identifier.

**Coverage is a set comparison.** Missing, unexpected and duplicate draft ids
are counted separately, and a run that is not `complete` returns `ok: false`
with `GENERATION_INCOMPLETE` **and its partial output attached**. Nine drafts
with one duplicate and one omission is incomplete, and the ledger says which.
A truncated reply is rejected even though the transport reports success.

## The operator's rule, enforced in three places

> Most of the time evidence should be there, but attackers can always change
> tactics, so it shouldn't exclude the generated path.

`actor_evidence: false` **never excludes a node or a path**. It is stated in
the system context ("including steps whose actor evidence is false"), it is
carried into the draft's assessment block, and two tests hold it: a pair with
two nodes forced to false still produces nine of nine drafts, and a node with
`telemetry_readiness: none_declared` is drafted too, with its gap stated. Weak
evidence lowers confidence and is recorded; it is not a filter.

## Manifest change

`model_tier: heavy`, `requires_llm: true`, `timeout_class: slow`,
`cost_hint: moderate`. The plugin now holds a real provider call, which is what
`safe_for_auto_invoke: false` was always anticipating (decision 7).

## The first live run found a real defect

`generate_detections` was run against `gcp_gemini` on an 11-node pair. The
provider answered — roughly 90 seconds for the first batch — and the plugin
then died:

```text
✗ Error: 'str' object has no attribute 'get'
```

**Our defect, not the model's.** The validation code treated a reply as
untrusted *content* but trusted its *shape*: `draft["x_eventmill"].get(...)`,
`logsource.get("product")`, `entry.get("source_id")` for each telemetry item.
A model that returns `x_eventmill` as a string, or `telemetry` as a list of
source names rather than objects, is not malformed JSON and parses cleanly —
it just is not the shape the contract asked for. One such draft crashed a run
that had already been paid for.

Fixed with `as_dict()` / `as_dicts()` / `draft_id_of()` in `generation.py`,
used at every nested access; a `_shape_problems()` check that reports the
wrong type by name (`x_eventmill is str, not an object`); and a catch-all in
the tool loop so an unanticipated shape costs **its own node**, not the whole
run. Eight tests cover it, parametrised over the six ways a draft can arrive
misshapen, plus a reply that is a list of strings, plus the helpers themselves.

Two lessons worth keeping: a provider reply is untrusted shape as well as
untrusted content, and a crash after a paid call is strictly worse than a
rejection — the other batches' work was lost with it.

**Also added:** the digest now carries `telemetry stream_available (N)` on its
detail line. The digest is the free pre-flight check before a paid call, and
readiness — the field that most predicts whether a draft can name anything
concrete — was missing from it, because G1a landed after the digest was
written.

## The second live run found a worse one: cross-estate contamination

With the shape fix in, the digest showed `telemetry stream_available (5)` on
`telemetry_db`. Five is wrong. Two were right — `postgres.session` and
`pgaudit.object_access` — and three were the loyalty estate's bespoke systems
leaking onto a telemetry SaaS warehouse because both happen to run Postgres:
`ledger.adjustment_audit`, `finance.points_liability_reconciliation` and
`baseline.redemption_velocity`.

**This is worse than the crash it followed**, because nothing would have
caught it. The model would have been offered "Loyalty ledger adjustment audit
log" for a telemetry warehouse, might reasonably have cited it, and validation
would have **accepted** the draft — the source *was* offered. A plausible,
confident, wrong detection, produced by the one check meant to prevent exactly
that.

The cause is the seed: a real library describes one estate, this one describes
five, and technology matching cannot tell whose Postgres is whose. Entries that
describe a bespoke system now carry `applies_to.scope: estate_specific` (8 of
36), the estate is derived from the supplied map's filename, and such entries
attach only to their own estate. With no estate key nothing is filtered, which
is the right default for a library holding only the operator's systems.
Library **v0.3.0**.

Readiness across the corpus moves to **38 `stream_available`, 5
`none_declared`** — and the two `periodic_only` nodes disappear, because they
were loyalty reconciliation entries attached to `claims_db` and `oracle_db`.
The five bare nodes now have two honest reasons: `claims_db`, `doc_store` and
`users` declare no technologies; **`oracle_db` declares `oracle`, which the
seed library does not cover at all.** Application B runs Oracle, Mongo and
Cosmos and the seed has none of them — a recorded gap, and the first thing to
close if that estate is used in earnest.

## Verified, and not

- 42 new tests; full suite 1749; 36 schemas valid; manifest validation
  unchanged at its 15 pre-existing `stability` errors.
- The catalogue test caught `LLM_UNAVAILABLE` and `GENERATION_INCOMPLETE`
  missing from spec §4.4 before this entry was written.
- **One live call made**, against an 11-node pair on `gcp_gemini`. It reached
  the provider, returned in about 90 seconds, and crashed the plugin on the
  reply's shape. The fix is above; the drafts themselves have still never been
  read, so nothing is yet known about their quality.
- No workbook yet: drafts are returned as JSON, and the YAML/Markdown
  rendering plus its sidecar are G1d. PyYAML remains undeclared in
  `pyproject.toml`.
- `ruff`, `black` and `mypy` are not installed in this environment.
