# Change Log — Stage E: the live cross-vendor projector run

**Date:** 2026-09-14
**Branch:** `llm_5`
**Primary Files Modified:** `AGENTS.md`,
`framework/llm/providers/openai_daybreak_red.json`

No application code changed. This records the operator's live run of
`adversary_path_projector` across vendors — Stage E of
`docs/specs/projector_three_vendor_run.md`, the stage the previous four were
built to make possible — and narrows the claims the repo makes as a result.

---

## What was run, and what it showed

Reported by the operator, qualitatively:

- **`gcp_gemini` heavy (`gemini-3.1-pro-preview`) against
  `openai_daybreak_red` (`gpt-daybreak-red-latest`)** on the same
  `adversary_path_projector` workload. Both jobs **completed properly**, and
  the **outputs were very similar**.
- **`openai` and `anthropic`** both worked.
- **`--action summarize_run_group`** worked as expected.

That closes the envelope questions Stage E existed to answer. The ones worth
naming separately, because each was a distinct risk:

1. **`_parse_llm_json` holds across vendors.** It was tuned against Gemini's
   habits, and the spec flagged it as becoming load-bearing the moment a
   second vendor answered. Runs completing means no parse failure and no
   truncation on the other vendors' output shapes.
2. **The group summary reads a mixed group.** Stage D gave it a provider
   dimension with no live mixed group to read; now it has read one.
3. **`needs_structured_output` being inert did not matter.** Nothing in any
   client sets a response schema, so JSON arrives because the prompt demands
   it. It arrived.

## The finding that was not on the risk list

**Two independent vendors produced very similar output.** That is the happy
outcome for the envelope and an uncomfortable one for the metric: the
agreement grade exists to ask "does this route survive a change of reasoner?",
and its answer is only worth something if a change of reasoner could plausibly
have produced a different one.

Close convergence between Google and OpenAI is at least as consistent with the
prompt being highly constraining — a fixed flow map, a fixed actor, a
demanded output shape — as with independent confirmation of the routes. On
this evidence the grade measures *"the prompt admits few readings"* about as
much as it measures *"the finding is robust"*, and it should not yet be
presented to an analyst as the latter alone.

This does not make the grade wrong or the dimension wasted. It makes its
discriminating power an open empirical question, and one that a
single-flow-map comparison cannot settle either way. A flow map with genuinely
ambiguous routes is what would.

## What this does NOT settle

**The provider-vs-vendor grading decision is still open.** `_agreement_grade`
(`tool.py:2403`) counts what `_provider_of_record` returns, which is
`model.provider` — a provider id, not a vendor. The question it leaves open is
whether `openai`, `openai_daybreak_red` and `openai_daybreak_blue` finding one
route is three opinions or one.

Gemini-versus-Red does not answer that, and it is worth being exact about why:
those are two *different* vendors, so the pair exercises the case the grade
already handles correctly. The unresolved case is **two provider ids sharing a
vendor**, and the cleanest instance of it is Red against Blue. Blue has still
never been called.

So the grade stays counting provider ids, deliberately, for the same reason as
before — and the new convergence finding above is a reason to be *more*
careful about flipping it on thin evidence, not less. `model.vendor` continues
to be recorded (run record schema v5) so the decision stays available.

## What was not measured

The operator's sign-off is qualitative. Not captured, and therefore not
claimed anywhere in the repo:

- **Runs per vendor.** The parent plan's acceptance is n ≥ 5 per vendor, with
  3 the minimum that makes recurrence countable at all
  (`MIN_RUNS_FOR_RECURRENCE`).
- **Scoring against `stepstate-medium-2`**
  (`docs/change_log/2026-09-11-live-run-findings.md:158`) — rejection count at
  or below baseline is the formal per-vendor acceptance criterion.
- **Whether the similarity was route-level or narrative-level.** "Very similar"
  is the operator's reading of the reports, not a computed agreement figure,
  and the distinction is exactly what the section above turns on.

Red's manifest therefore stays **PARTIAL**. What the run adds to it is that the
heavy tier sustained a real workload and tracked another vendor's answer on it;
what it does not add is any measured token limit, or any `thinking_level` other
than the projector's `medium`.

## Next

1. **Probe Blue, then Red against Blue** in one `run_group`. Unchanged as the
   next step, and now the *only* thing gating the grading decision.
2. **A flow map with ambiguous routes**, if the agreement grade is to be
   trusted as a robustness signal rather than a convergence observation.
