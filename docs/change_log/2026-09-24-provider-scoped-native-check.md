# 2026-09-24 — Native-document check and output limits follow the operator's provider

A live `threat_intel_ingester` run on OpenAI, with Gemini also bound, planned
`native_batched: 9 batch(es)` for a 91-page PDF. OpenAI refused every batch
with *"model gpt-5.6-terra lacks native support for application/pdf"*. All 91
pages then went to the chunked text path, which completed normally.

## What was actually wrong

**OpenAI not reading PDFs is expected.** It has no document path yet:
`openai.json` doesn't declare `native_pdf`, and `OpenAIClient.query_with_document`
is a stub pointing at Stage 3. The text fallback was the right outcome. Two
defects made the run look broken on the way there:

1. **`supports_native_document` answered for any connected provider.**
   `LLMDispatcher.supports_native_document` returned True if *any* connected
   client could read the MIME type, and `TierScopedLLMClient` never passed the
   operator's provider inward. With Gemini bound, a plugin pinned to OpenAI was
   told native PDF was available. Routing never crosses providers, so that
   answer could never be acted on. Both report tools gate on this call.
2. **Both report tools sized replies with the default provider's figures.**
   `threat_intel_ingester` (native plan and call cap) and
   `threat_report_analyzer` (`_budget`) read `max_output_tokens_for_tier` and
   `thinking_reserve_tokens` with no provider, so they always got Gemini's
   numbers. The run's `cap 36864` is Gemini's (65,536 − 16,384) × 0.75
   headroom. On OpenAI it is now 83,712. The dispatcher clamps anything over
   the cap, so nothing failed. But CLAUDE.md forbids reading one provider's
   limits for another, and it would have split documents wrongly as soon as a
   second provider read PDFs.

## Changes

- `LLMDispatcher.supports_native_document(mime_type, provider=None)` answers
  only for the named provider, or for the session default when none is named.
  That is the provider `query_with_document` would route to.
- `TierScopedLLMClient.supports_native_document` passes the operator's
  provider inward. The plugin-facing signature still has no `provider`
  parameter.
- New `OutputLimits(max_output_tokens, thinking_reserve_tokens)` and
  `output_limits(tier, level, provider_id)` in `framework/llm/providers`. Both
  figures come from one provider, because a cap from one vendor with another's
  reserve describes a call nobody can make.
- `LLMDispatcher.output_limits(...)` and `TierScopedLLMClient.output_limits(tier=None,
  thinking_level=None)` resolve the provider the same way routing does. The
  plugin gets the figures for the model that will run without learning or
  choosing the vendor. The method is declared on `LLMQueryInterface`.
- Both report tools read limits from the handle. A handle that can't answer
  (a test fake, or no LLM) falls back to the default provider's figures,
  which is what every run used before.

This implements part of the spec's outstanding "provider-qualified accessors"
item. The spec proposed `output_budget()` and `max_output_tokens()` as two
methods. This change uses one method returning both figures, so they cannot come
from different providers.

## A gap this exposed, not fixed here

`anthropic.json` declares `native_pdf` on both tiers, but
`AnthropicClient.query_with_document` is also a stub (Stage 4). After this
change, an **Anthropic-pinned** run still plans native batches and has each one
refused, which is the same symptom this change removes for OpenAI. The
capability flag is true of the model, not of our client. How to close it is a
decision in the Stage 3 plan (`docs/specs/openai_document_path_plan.md`).

## Checked

- 20 new tests: 14 framework, 3 ingester end to end through the real
  dispatcher and wrapper with two fake providers, and 3 analyzer.
- Each test was run against its defect with the change reverted:
  - Removing the dispatcher's provider filter fails 4 tests; dropping only
    the wrapper's scoping fails 2.
  - With the ingester ignoring the handle's limits, the cap test fails.
  - With the analyzer ignoring the handle's limits, 2 tests fail.
- Full suite **1844 → 1864**, all passing.
- `ruff` isn't installed in this environment. New lines were checked by hand
  against the 88-character limit.

**Not run live.** The first live check is the same OpenAI run as above: it
should now log `[PLAN] chunked_text` and make no `[NATIVE]` calls.
