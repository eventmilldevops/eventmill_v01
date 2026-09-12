# Change Log — projection hardening, LLM retry, and reasoning-depth control

**Date:** 2026-09-09
**Primary Files Modified:**
`plugins/threat_modeling/adversary_path_projector/tool.py`,
`plugins/threat_modeling/adversary_path_projector/schemas/input.schema.json`,
`plugins/threat_modeling/adversary_path_projector/schemas/output.schema.json`,
`plugins/threat_modeling/adversary_path_projector/tests/test_contract.py`,
`framework/llm/client.py`
**Supporting Files:** `tests/framework/test_llm_dispatcher.py`, `.env.example`

Follows `2026-09-09-adversary-path-projector-phase-2.md`. Everything here came
out of auditing live projections rather than from the plan.

---

## 1. Tactic correction replaces tactic warning

Phase C previously kept the model's tactic label when the technique did not
carry it, and filed a warning. That is the weakest available option, and it is
what let a bad label reach `_ACCESS_BY_TACTIC` and produce nonsense access
levels.

The technique database makes correction possible rather than merely detection:

```
enterprise techniques: 697
  1 tactic:   552  (79.2%)
  2 tactics:  120  (17.2%)
  3 tactics:   20  (2.9%)
  4 tactics:    5  (0.7%)
techniques with NO tactics listed: 0
```

Four times out of five the right answer is not just knowable but unique. So
`_resolve_step_tactic` now:

- **single-tactic technique** — overwrites with the only valid tactic.
  "T1190 / Impact" becomes Initial Access.
- **multi-tactic technique** — `_closest_tactic` picks the earliest candidate
  at or after the previous step's kill-chain position, so a correction carries
  the chain forward. It excludes `Initial Access` past the first step:
  correcting a mid-chain T1078 must not manufacture a second entry point.
- **retired name** — unchanged, resolves through `resolve_legacy_tactic`.

**Correction, not rejection, is deliberate.** A technique outside the closed set
is unsupportable and gets discarded. A mislabelled tactic is usually the right
technique with the wrong word — T1190 on an internet-facing Django app is
correct regardless of what the model typed — and discarding the step would
strand the `leads_to` edges either side and split the graph. The repair would
cost more than the error.

The corrected tactic is what feeds `_ACCESS_BY_TACTIC`, so a mislabel can no
longer poison the access levels downstream.

## 2. Kill-chain sequence checks

Tactic-vs-technique mismatch is a labelling error. Tactic-vs-*position* is the
signal that the model misunderstood the technique, and nothing checked it.

- `KILL_CHAIN_REGRESSION` — a step whose tactic drops more than
  `TACTIC_REGRESSION_THRESHOLD` (6) positions from the previous step. Real
  chains loop (Lateral Movement back to Discovery, C2 back to Credential
  Access), so small regressions are normal and must not be flagged; a large one
  means a late-stage action landed before the work that enables it.
- `LATE_INITIAL_ACCESS` — Initial Access after the first step, when access was
  already gained upstream.

Both are warnings, **including the regression check**, which had been floated as
a rejection candidate. Same reasoning as above: rejecting strands edges, and a
step in the wrong position usually still belongs in the path. They annotate the
step and surface in `summarize_for_llm()` — a warning nobody reads is not a
warning:

```
N step(s) out of kill-chain sequence — review: <locations>
N tactic label(s) corrected against ATT&CK.
```

## 3. `framework/llm/client.py` — a 504 was never retried

`_is_retriable` carried the marker `"DeadlineExceeded"` (camelCase). Google
emits `DEADLINE_EXCEEDED` (screaming snake), and `"504"` was absent entirely:

```
503 UNAVAILABLE           True
429 RESOURCE_EXHAUSTED    True
504 DEADLINE_EXCEEDED     False   <-- the one long generations actually hit
```

So the retry loop with exponential backoff (`max_retries=3`, 1s/2s/4s at lines
430, 483 and 1218) fired for quota and unavailability but treated a transient
gateway timeout as fatal. A live projection failed outright at ~110s instead of
backing off one second and succeeding.

Fixed by adding `"504"` and `"DEADLINE_EXCEEDED"` alongside the existing
camelCase form. **This affects every LLM-using plugin, not just the projector.**
Free-tier quota exhaustion still correctly refuses to retry.

## 4. Reasoning depth is now stated, not inherited

`client.py:72` resolves an unset `thinking_level` to `"high"` whenever
`needs_reasoning` is set:

```python
if level is None and hints.needs_reasoning:
    level = "high"
```

`project_paths` passes `needs_reasoning=True`, so every projection had been
running at **high** — the real cause of the ~110s latency, not prompt size.

Measured on the same command against the 7-component example map:

| thinking_level | Result |
|---|---|
| `high` (inherited) | 504 DEADLINE_EXCEEDED after ~110s |
| `medium` (stated) | complete in 27s |

Roughly 4x, with the reasoning quality holding — the same architecture-specific
placement, still routing through the unauthenticated S3 flow.

The plugin now states its own floor rather than inheriting the dispatcher's:

- `DEFAULT_THINKING_LEVEL = "medium"` (`tool.py`)
- `EVENTMILL_PROJECTION_THINKING` env override, named after the existing tier
  overrides in `framework/llm/providers/__init__.py`
- `--thinking_level` per call

Precedence mirrors the tier rule in CLAUDE.md: **per-call > env > default**.
`_default_thinking_level()` reads the env at *call* time, not import time —
`PluginLoader` imports the module during `EventMillShell.__init__`, and a `.env`
loaded in `main()` has to still apply. A bad value warns and falls back rather
than failing the run; an operator typo should not cost a projection.

This is a reasoning floor, not a cost saving. Deep reasoning about how an actor
would move through a *specific* architecture is the value over re-summarising
ATT&CK, so raise it wherever latency allows — Cloud Run has more headroom than
an interactive session.

## Tests

Plugin 157, full suite 808. New coverage:

- tactic correction for single- and multi-tactic techniques, that correction is
  not rejection, that it does not introduce a second entry, and that the
  corrected value is what reaches the access table
- kill-chain regression flagged, **and a normal Lateral Movement to Credential
  Access loop not flagged** — a false-positive-prone check is worthless
- `tests/framework/test_llm_dispatcher.py::TestTransientErrorClassification` —
  the exact 504 payload observed, both spellings, permanent errors, and
  free-tier quota still refusing to retry
- env override precedence, case-insensitivity, call-time reads, and that a bad
  env value does not make every payload fail validation

## Still open

- Streaming is the structural fix for latency. `generate_content_stream` is used
  nowhere; every call is a blocking `generate_content` and so is exposed to the
  gateway deadline in full. `medium` buys headroom rather than removing the
  ceiling — a large flow map at `high` will still find it.
- `http_options={"timeout": 120_000}` at `client.py:196` is a framework choice,
  unexamined against the provider's own gateway deadline.
