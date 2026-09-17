# Change Log — Daybreak Red verified on Cloud Run; Blue still unproven

**Date:** 2026-09-14
**Branch:** `llm_5` (implementation pushed as `f84adfc`)
**Primary Files Modified:** `framework/llm/providers/openai_daybreak_red.json`,
`framework/llm/providers/openai_daybreak_blue.json`, `AGENTS.md`,
`docs/change_log/2026-09-14-daybreak-providers.md`

No application code changed. This records the operator's live verification and
narrows the two manifests' `_verified` blocks to what was actually measured.

---

## What was verified

`openai_daybreak_red`, in the deployed Cloud Run container:

- `providers probe openai_daybreak_red` — the alias is present in the model
  listing, and the few-token ping returned non-empty text.
- A full `project_paths` run completed, and its record validated against
  `projection_run.schema.json`.

Three things follow, and they are worth separating because they were three
separate risks when this was written:

1. **The alias is real.** `gpt-daybreak-red-latest` was carried from an
   external assessment and had never been checked against `models.list`.
2. **The secret is what it was claimed to be.** `eventmill-anthropic-daybreak`
   — a name whose `anthropic` substring is a storage label — holds an OpenAI
   credential entitled to this model, and mounts to `OPENAI_DAYBREAK_API_KEY`.
3. **The deploy wiring holds.** Running in the container means the
   `cloudbuild.yaml` mount, the `deploy-cloudrun-secrets.sh` allowlist and the
   `_LLM_PROVIDERS` default all agreed. A drift in any one of them would have
   shown up as a provider that was simply missing.

The heavy tier answered a long structured-output prompt end to end, which is
the actual workload — `connect` proves only that an SDK handle was built, and
a probe ping proves only that the key reaches the vendor.

## What was NOT verified, and is now said so in the manifests

**Blue has never been called.** It is registered, deployed, and shares Red's
credential — but no probe and no run have touched it. Its manifest now says
that explicitly, including the trap: a working Red is **not** evidence that
Blue is entitled on the same key. Entitlements are granted per model.

**Red's numbers are still documented, not measured.** `max_output_tokens` and
`max_context_tokens` were not read from an over-limit 400 the way
`openai.json`'s were. `thinking_levels` has only been exercised at `medium`,
the projector's default, so `low` and `high` remain assumed and whether this
model rejects `minimal` the way gpt-5.6 does is still unknown. Capabilities
beyond `text`, `structured_output` and `deep_reasoning` stay unclaimed.

Red's `_verified` is therefore marked **PARTIAL** rather than promoted to the
shape `openai.json` uses. The distinction matters: that block is the repo's
record of what was measured, and a partial verification written as a complete
one is the failure the block exists to prevent.

## Unchanged, and still open

`_agreement_grade` still counts provider ids rather than vendors. Deciding it
needs Red **and** Blue producing comparable runs over the same flow map, which
a Red-only verification cannot settle. `model.vendor` is being recorded in the
meantime (run record schema v5).

## Next

`providers probe openai_daybreak_blue`, then the controlled A/B: same actor,
same flow map, same `run_group`, both colours, then `summarize_run_group`. That
run is also what decides the grading question above.
