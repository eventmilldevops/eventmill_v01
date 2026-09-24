# 2026-09-24 — A 91-page OpenAI run crashed after its last batch; nothing was saved

The first live run after native PDF landed on OpenAI
(`2026-09-24-openai-anthropic-native-pdf.md`) did what that entry promised
until the end:
- It planned `native_batched: 9 batch(es)` with OpenAI's own cap (83,712).
- It ran every batch natively for about 500 s.
- It merged them, logging `[MERGE] 3 reported value(s) disagree`.

Then it died with `TypeError: unhashable type: 'dict'`. The exception
escaped `execute()`, so **no artifact was written**, and the whole run was
paid for and lost.

## Cause

The model's JSON is untrusted in shape. The post-merge code hashes or looks
up several fields the model controls: `confidence` goes through
`confidence_order.get(...)`, and `related_mitre` entries go through a
`seen_techniques` set. A dict in either place raises. The merge's own
set and key operations (technique ID and tactic, convergence points)
survived this run, because the `[MERGE]` warning is logged after the merge
returns. They would raise the same way on a list-valued tactic.

The prompt invites the likeliest version of this. Its format shows
`related_mitre` as ID strings (`["T1234", "T1234.001"]`), but Section 4
says *"For EVERY technique in both refined_iocs.related_mitre AND
additional_mitre_techniques, you MUST populate the 'tactic' field"*. Only
an object can carry a tactic. **This is inferred, not confirmed:** the Cloud
Run log carried no stack trace (see below), and the 91-page report isn't
available locally.

## Changes

- **`_coerce_result_shape()`** normalises each batch where results enter
  `_merge_llm_chunk_results`:
  - Scalars given as objects or lists are flattened to text.
  - `confidence` and `priority` are forced into low/medium/high, defaulting
    to low and medium respectively.
  - `related_mitre` becomes a list of ID strings, pulling `technique_id`
    out of objects.
  - `is_false_positive` given as a string becomes a bool.
  - Non-object entries are dropped.
  - `convergence_points` and `branch_points` are flattened to strings.

  A well-shaped result passes through unchanged.
- **Every normalisation is logged** as
  `[SHAPE] <batch>: the model returned N field(s) in a shape the prompt did
  not ask for, normalised: ...`, so the drift stays visible.
- The per-batch `[NATIVE] ... parsed` and `[DIAG] Chunk ... parsed` log lines
  run *before* the merge, so they count from the same normalised view.
- **Tracebacks now reach Cloud Logging.** The JSON formatter kept only
  `type` and `message` from `logger.exception`; it now adds `stack_trace`.
  This crash named no line, and on Cloud Run that log record is the only
  copy.

## Considered and reverted: fixing the prompt

I rewrote Section 4 so tactics apply only to `additional_mitre_techniques`,
with `related_mitre` stated to be ID strings. Live runs on the probe PDF
(OpenAI, whole document) were inconclusive:

| Prompt | Non-technique results, separate runs |
|---|---|
| Edited | 0, 0, 62 |
| Original | 62, 62, 52 |

Both zeros were runs where the model marked **every** candidate as a
false positive. The same judgement appeared with the original prompt
when the probe was batched: its documentation-range addresses and reserved
domains read as test data to gpt-5.6-terra. Three runs can't separate a prompt
effect from that variance. The edit isn't needed to stop the crash, so it
was **reverted**. **The contradiction is still in the prompt, and fixing it
is a decision for the operator.** A proper comparison needs a fixture with
real-looking indicators, so that test-data rejection doesn't swamp the
signal.

## Correction to the native-PDF entry

`2026-09-24-openai-anthropic-native-pdf.md` reports OpenAI's whole-document
probe run as 62/82, as if stable. It isn't. Three whole-document OpenAI
runs with the original prompt gave 62, 52 and 62, and the edited prompt
produced two runs where every candidate was marked false positive. Anthropic and Gemini weren't repeated. **On this probe, OpenAI's
false-positive judgement varies from run to run**, so the 91-page rerun
should be compared against Gemini on `candidates_rejected`, not only on
whether it completed.

## Checked

- `TestUntrustedShapeCannotCrashTheRun`, 3 tests:
  - A **batched** end-to-end run whose model returns objects for
    `confidence`, `priority`, `context` and `related_mitre`, a string for
    `is_false_positive`, a list tactic, object convergence points and a
    null `branch_points`. It completes, **registers its artifact**, and
    every field comes out in the documented shape.
  - The drift is logged.
  - A well-shaped result is untouched.
- Mutation: with the normalisation bypassed, the end-to-end test fails
  with `TypeError: unhashable type: 'list'`, the same class as the Cloud
  Run crash.
- Full suite **1886 → 1889 passed, 1 skipped**.

**Not yet run:** the 91-page report itself. Rerun it on Cloud Run. It should
complete, save its artifact, and log any `[SHAPE]` lines, which will show
what gpt-5.6-terra actually returned. If it fails again, the log now carries
the stack trace.
