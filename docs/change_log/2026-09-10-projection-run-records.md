# Change Log — projection run records, `--runs`, and a missing `model_used`

**Date:** 2026-09-10
**Primary Files Modified:**
`plugins/threat_modeling/adversary_path_projector/tool.py`,
`plugins/threat_modeling/adversary_path_projector/schemas/projection_run.schema.json` (new),
`plugins/threat_modeling/adversary_path_projector/schemas/input.schema.json`,
`plugins/threat_modeling/adversary_path_projector/tests/test_contract.py`,
`framework/llm/client.py`
**Supporting Files:**
`plugins/threat_modeling/adversary_path_projector/examples/README.md`

Follows `2026-09-10-flow-map-examples-and-authoring-guide.md`.

---

## Problem

Projection is sampled, not deterministic. The same actor against the same flow
map does not produce the same paths twice, and nothing recorded enough about a
run to tell a real finding from a one-off.

The plugin was not keeping *nothing* — `_write_projection_artifacts` has emitted
an attack graph and a scenario seed per run since Phase 2. What those artifacts
lack is provenance: which model ran, at what reasoning depth, against which
version of the map, and what the deterministic layer computed before the model
was called. Two runs were indistinguishable, and a failed run left no trace at
all.

## Changes

### `--export`, `--run_group`, `--runs`

Opt-in. Absent `--export` the one-run result keeps exactly the shape it had.

- `--export` — write a provenance record per run.
- `--run_group` — operator label tying a comparison set together, slugged,
  defaults to `ungrouped`. Recorded as metadata, **not** as a directory.
- `--runs` — 1 to 25, default 1. Repeats the projection in one invocation and
  **implies `--export`**: a loop that leaves no record cannot be compared,
  which is the only reason to run one.

At `medium` on a ten-component map a run is ~30-40s, so the cap keeps a
ten-minute invocation a deliberate choice rather than a typo.

### Records are registered artifacts, not a `--export_dir`

The first draft of this task specified an operator-supplied output directory.
That was rejected on two structural grounds, and the change is worth recording
because the same reasoning applies to anything else that wants to write files.

CLAUDE.md states that a plugin receives a read-only `ExecutionContext` and that
`context.register_artifact()` is the one write it may perform; an arbitrary
output path is a second, unregistered write. And the runtime switches artifact
resolution to GCS when it detects `K_SERVICE`, so a local directory would write
to ephemeral container storage on Cloud Run and lose the corpus silently when
the instance recycled — the same class of failure the bucket-prefix guard
exists to prevent.

So records go to `$EVENTMILL_WORKSPACE/artifacts/` through the existing
write-then-register path, as
`adversary_projection_run_<stamp>_<run_id[:8]>.json`. The stamp is
second-resolution, so it is the run id suffix that keeps a `--runs 10` loop from
colliding with itself. Nothing is ever overwritten.

In a loop the graph and seed are written **once, for the first successful run**.
Every run still gets its own record. A twenty-run experiment otherwise buries
the artifact listing under forty files nobody asked for.

### The record: `deterministic` vs `sampled`

This split is the point of the whole change. Everything under `deterministic` is
fixed by `flow_map_sha256` and must be identical across runs, so a reader
comparing two records knows any difference below it came from the model.

- **`run`** — ids, timestamps, `flow_map_sha256`, resolved actor.
- **`model`** — provider, tier, and the **resolved** `thinking_level`.
- **`deterministic`** — entry ranking, routes, unreachable crown jewels,
  validation warnings. Computed once per invocation and copied into each record;
  recomputing per iteration would only cost time.
- **`sampled`** — the model's paths, `technique_id` first-class rather than
  embedded in prose, because that is what a reader scans down a column.
- **`outcome`** — status, verbatim provider stop reason, token usage including
  thinking tokens, wall time.

`flow_map_sha256` is computed over a canonical serialisation of the map **as
supplied, before normalization** — sorted keys, no insignificant whitespace.
Hashing the normalized map would be wrong: normalization fills defaults, so two
files differing only in an omitted-vs-explicit default collapse to the same
thing. A test asserts exactly that divergence.

`tool_version` carries **both** `manifest_version` and `git_sha`. The manifest
has read `0.2.0` since Phase 2 while tactic correction, the kill-chain checks
and the thinking-level default all shipped after it, so the manifest version
alone cannot separate a pre-hardening run from a post-hardening one. The SHA is
read from `.git` directly rather than by shelling out, and cached.

`thinking_level` records the **resolved** value. `_default_thinking_level()`
reads the environment at call time and an unset level becomes `"high"` in
`client.py` whenever `needs_reasoning` is set, so what was asked for and what
ran can differ — and that is the variable that separated a 504 at ~110s from a
completion at 27s.

### Raw replies are now retained

Deliberately added, not inherited. `response.text` was parsed and dropped; under
`--export` it is now kept as a sibling `text` artifact. With correlation done by
eye, when two runs disagree the parsed record shows *that* they diverged and
only the raw reply shows why.

### Failed runs export — the authorised refactor

Every failure path previously returned a `ToolResult` before reaching the
artifact writer. Phase B+C moved into `_run_one_projection`, which returns the
attempt **as data** so a failure can be recorded before it is returned;
`_single_run_result` rebuilds the identical `ToolResult`. All four paths — query
failure, truncation, parse failure, `PROJECTION_REJECTED` — keep their exact
error codes, messages and `details`.

`sampled` is **absent** on a failure rather than empty. An empty block reads as
"the model returned nothing", which is a different event from never having got a
usable reply.

This matters most inside a loop: at `high` a run can hit the gateway deadline,
and a dead run must not stop the ones after it. A map that reliably fails at a
given reasoning depth is a finding about the map, and it disappears if only
successes are recorded.

Records are written pre-loop for nothing: actor errors, map errors, an empty
closed set and `LLM_UNAVAILABLE` all return before any record, because they are
configuration or input errors rather than run outcomes — and `LLM_UNAVAILABLE`
under `--runs 10` would otherwise write ten identical records.

### `framework/llm/client.py` — `model_used` was never set on the text path

Found because a live run recorded `model_configured: null`.

`MCPLLMClient.query_text`'s success return omitted `model_used` entirely. So did
`query_multimodal`. The document path and every error path set it, which is why
it was never noticed. `LLMResponse.model_used` is documented in `protocol.py` as
"which model actually ran" and was `None` for every ordinary text query in the
repo.

Fixed by adding `model_used=self.model_id` to both returns. **This affects every
LLM-using plugin, not just the projector** — the projector's own
`result["model_used"]` had been `null` on every text-path projection since Phase
2. Verified live: the field now reads `gemini-3.1-pro-preview`.

## Verified against the live API

APT29 against `telemetry_saas_flow_map.json`, Gemini 3.1 Pro, `thinking_level`
medium.

Single run with `--export`: 25,952ms, `finish_reason` STOP, 4,870 prompt /
1,073 completion / **1,933 thinking** tokens, two paths, zero rejections.

`--runs 3` on the same map:

```
run 1  ok  2 paths  6 steps  39940ms
run 2  ok  2 paths  7 steps  31848ms
run 3  ok  2 paths  8 steps  40820ms
```

One `flow_map_sha256` and **one distinct deterministic block across all three
records** — the invariant holding on real data rather than only in a test. The
corpus answers its own question immediately:

```
stable across all three : T1078.004, T1059.006  (scm -> ci_runner)
in one run only         : T1005 T1021.007 T1059.009 T1190 T1199
                          T1505.003 T1528 T1595.002 T1621 T1651
```

The supply-chain entry through source control into the CI runner reproduces;
almost everything else is sampling variance. That is the comparison the records
exist to support.

## Tests

Plugin 192, full suite 843 (was 157 and 808). 35 new, covering canonical hashing
including that raw and normalized maps diverge, schema validation of both a
successful and a failed record, all three failure modes recording an error with
no `sampled` block, `--runs` writing one record each with no record modified by a
later run, a failing run not stopping the rest, the graph artifact written once
per loop, the multi-run summary staying inside the 2000-character cap, and an
unwritable workspace keeping the projection.

The deterministic-stability test is built **without an LLM** —
`validate_flow_map` is that layer standalone, so the comparison needs no model
and no mocking around one.

`validate_manifests.py` still reports exactly the 15 pre-existing `stability`
errors.

## Outstanding

**The response-reported model id is still not captured.** `model_configured`
now holds the id the client was *configured* with, which is what the fix above
delivered. It is not the id the API response reports: Gemini returns
`model_version` and nothing reads it, and `LLMResponse` has no field to carry
it. A silent provider-side bump behind `gemini-3.1-pro-preview` remains
invisible in this corpus. Closing it needs a new `LLMResponse` field plus
capture in `client.py` — a framework change touching every LLM plugin, and its
own task. The schema's `model_configured` description says so explicitly rather
than letting a later reader assume otherwise.

**Records written before today's `client.py` fix have `model_configured: null`.**
They remain valid records; that one field cannot be read for them.

**No comparison tooling exists, by design.** Clustering, frequency counts,
agreement scoring and diffing are all out of scope. The first version of
comparison is a human opening two records from the same `run_group`. The record
shape was chosen for that reader — `technique_id` as a scannable column, the
raw reply one file away.

**Multi-model comparison is a separate path.** The `model` block does not
attempt to abstract over providers and hardcodes `provider: "gcp_gemini"`.
Adding a second provider means revisiting it.

**Orchestration stays thin on purpose.** `--runs` is a loop in one invocation,
nothing more — no scheduling, no parallelism, no cross-invocation grouping
beyond the operator-supplied `--run_group` string. Runs are sequential, so
twenty runs is twenty times one run's latency.

**Records are unprotected.** They contain estate topology, trust boundaries and
the implementation status of every control including the missing ones; the
retained raw reply adds a model's reasoning about exploiting them. Written with
default filesystem permissions, no encryption, no redaction. Noted in the README
rather than solved.

**`ruff` and `black` were not run** — neither is installed in this environment
(`No module named ruff` / `black`). Style was matched by hand against the
surrounding file.

**Still open from 2026-09-09, unchanged.** Streaming is the structural fix for
latency and `generate_content_stream` is used nowhere, so every call remains
fully exposed to the ~110s gateway deadline; `http_options={"timeout":
120_000}` at `client.py:196` has still not been examined against it. Phase 3
(`export_scenario` / `import_scenario` on `threat_model_analyzer`) and Phase 4
(`normalize_flow_map`, plugin README) are untouched by this change.
