# Change Log — the provider seam is modular; Daybreak Red is the proof

**Date:** 2026-09-14
**Branch:** `llm_5`
**Primary Files Modified:** `AGENTS.md`,
`framework/llm/providers/openai_daybreak_red.json`

No application code changed. This closes out the Daybreak work by recording
what it actually demonstrated, and retires a planned experiment that is not
going to happen.

---

## The result worth keeping

**Adding a fifth provider worked the first time out.** `openai_daybreak_red`
went from nothing to probed, deployed and running a full
`adversary_path_projector` workload on Cloud Run without a single change to
`LLMDispatcher`, to any client, or to any plugin. The work was: one manifest
in `framework/llm/providers/`, one secret, and the deploy wiring already
built to carry a provider list.

That is the property the provider seam was designed for, and it had never
been tested end to end — `openai`, `anthropic` and `gcp_gemini` were all
built while the seam was being built, so none of them could prove it. Red is
the first provider added *after* the abstraction settled, which makes it the
first real test of it.

**The operator's read, and the one that matters for planning:** if Daybreak
Red is swapped for Kimi 3 in two weeks, it should still work. Nothing in that
swap touches code — a new `<provider_id>.json`, a key, and an entry in
`EVENTMILL_LLM_PROVIDERS`. The seam is the deliverable; Red is a tenant of it.

What is *not* claimed: that any new vendor's SDK is already spoken. Red reuses
the OpenAI transport (`clients/openai.py`), so it proves manifest-level and
routing-level modularity. A vendor with its own SDK surface needs a client,
which is a known and bounded piece of work — see
`docs/specs/multi_provider_llm_clients.md`.

## Red is temporary, and Blue is not coming

The operator has **short-term access to Red only**. Blue was registered
alongside it because they arrived as a pair, but it will not be exercised.

So the Red-versus-Blue A/B is **retired, not deferred**. Every previous log
named it as the next step and as the thing that would settle the grading
question below; that is no longer true, and leaving it written as "next"
would send the next reader looking for an experiment nobody intends to run.

Blue's manifest keeps its `UNVERIFIED` block unchanged. It is accurate, and
it is the right state for a provider that is registered but uncalled.

## The consequence: a decision that now needs judgment, not data

`_agreement_grade` (`plugins/threat_modeling/adversary_path_projector/tool.py:2403`)
counts what `_provider_of_record` returns — `model.provider`, a **provider
id**, not a vendor. It was left that way deliberately, pending live evidence
on whether one lab's two models are one opinion or two.

**That evidence is now never going to arrive.** The decision therefore has to
be made on reasoning, and the reasoning has not changed:

- The collision is **live today**, not hypothetical: `openai` and
  `openai_daybreak_red` are both `vendor: openai`, and both are bound by
  default. A route found by the two of them currently grades as two-provider
  agreement, which an analyst reads as two independent reasoners.
- The projector is **triage and must not overclaim** — the grade's own
  docstring says "does it survive a change of reasoner?", and two models from
  one lab on shared training lineage are a weaker instance of that than the
  grade implies.
- Stage E is a further reason for caution rather than confidence: two
  genuinely *different* vendors converged closely, so the grade's
  discriminating power is itself unproven (see
  `2026-09-14-stage-e-live-cross-vendor-run.md`).

**Recommendation: grade on `model.vendor`, not `model.provider`.** It is the
conservative direction — it can only lower a grade, never raise one — and the
field is already recorded (run record schema v5) precisely so this was
available. Left unimplemented here because it is a behaviour change to a
reported metric, which is the operator's call, not a tidy-up.

Recurrence stays per **provider id**. That is not the same question: "does
*this model* keep finding the route" is about one model's stability, and
collapsing `openai` and Red there would hide exactly the per-model variance
recurrence exists to measure.

## Next

Nothing on the provider seam. The open item is the PDF guard's missing
provider argument, which is now the active work.
