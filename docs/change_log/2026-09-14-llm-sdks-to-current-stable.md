# Change Log — LLM SDKs moved to current stable, OpenAI onto the Responses API

**Date:** 2026-09-14
**Primary Files Modified:** `pyproject.toml`,
`framework/llm/clients/openai.py`

**1036 tests pass**, unchanged. All six tier clients re-verified live.

---

## Why this reverses yesterday's ceiling

The first pass bounded each SDK to *the major it had been verified against*,
which for Anthropic meant `<1.0.0`. The operator pushed back, correctly:

> according to anthropic v0.x is legacy code and many things are deprecated.
> This is all net new code for this application so why wouldn't we be building
> on current stable? Doesn't need to be leading but I would like to stay out of
> deprecated.

That is the stronger argument. "Verified against" is a good reason to pin an
*existing* component; it is a bad reason to start *new* code on a deprecated
major. Both provider clients were written the previous day, so there was no
migration cost to avoid — only a migration cost to incur later, on purpose.

## Anthropic 0.111.0 → 1.5.0

The 1.x migration guide's inventory found **nothing to change**. The client:

- passes `timeout=180.0` and `max_retries=3` as plain values, so no `httpx`
  object crosses the SDK boundary and the `httpx2` swap does not reach it;
- does not use `with_raw_response`, so the awaited-body change is irrelevant;
- does not touch Text Completions, `temperature`/`top_p`/`top_k`, or
  `output_format` — all removed in 1.x, none of them ever used here, because
  the 5-family rejects sampling parameters anyway;
- uses `messages.create`, `messages.stream().get_final_message()`,
  `models.list()` and eight typed exception classes, every one of which exists
  unchanged in 1.5.0 (checked by introspection before editing, not assumed).

So the entire Anthropic change is the version specifier. Both tiers re-probed
green.

## OpenAI 1.58.1 → 3.13.0, and onto the Responses API

Two majors, and it removes a compromise rather than creating one. The client
used `chat.completions` **because** the installed SDK predated
`client.responses`; on 3.13.0 the surface the plan specifies is simply there.

| | Before | After |
|---|---|---|
| Call | `chat.completions.create` | `responses.create` |
| Prompt | `messages=[{role, content}]` | `input=` + `instructions=` |
| Budget | `max_completion_tokens` | `max_output_tokens` |
| Depth | `reasoning_effort="low"` | `reasoning={"effort": "low"}` |
| Usage | `prompt_tokens` / `completion_tokens` | `input_tokens` / `output_tokens` |
| Reasoning split | `completion_tokens_details` | `output_tokens_details` |
| Truncation | `finish_reason == "length"` | `incomplete_details.reason == "max_output_tokens"` |
| Failure | raises | **also reported on the object** (`status == "failed"`) |

The last row is the one that would have bitten silently: the Responses API
reports a failed generation on the response rather than raising, so reading
`output_text` alone turns a refusal into an empty-but-successful answer. The
client now checks `status` and `incomplete_details` before building an ok
response.

**`store=False` matters more here than it did before.** The Responses API
stores by default; `chat.completions` did not. Verified on a live call that the
returned object reports `store: False`. A no-retention posture for incident
data stays a declared property of this client.

Re-verified on the new surface, because a fact measured on one API surface is
not automatically true on another:

- `reasoning={"effort": "minimal"}` is **still rejected** — *"Unsupported value:
  'minimal' is not supported with the 'gpt-5.6-sol' model"*. So `openai.json`'s
  `thinking_levels` and `_effort()`'s clamp both still hold.
- Both tiers ping green. Latency rose from ~1.6 s to ~5 s on this surface;
  noted, not investigated, and irrelevant to a liveness probe.

## The pins now

| SDK | Declared | Installed | Rationale |
|---|---|---|---|
| `google-genai` | `>=1.69.0,<2.0.0` | 1.69.0 | **unchanged — see below** |
| `anthropic` | `>=1.5.0,<2.0.0` | 1.5.0 | current stable |
| `openai` | `>=3.13.0,<4.0.0` | 3.13.0 | current stable |

The dev venv satisfies all three declared ranges, and the "every LLM SDK
declares an upper bound" test still passes — the rule was never "pin to an old
major", it was "do not float across majors silently".

## google-genai is deliberately not included

It is the one component here that is **not** net-new: `GeminiClient` carries
every module, and its 1.x controls (`media_resolution`, `thinking_level`, the
response readers, the error classifiers) are what 974 tests and two live
verification sessions were run against. The same "stay out of deprecated"
argument may well apply to it — 2.23.0 is current, and the deployed container
has in fact been running 2.x by accident — but moving it is a real migration
with a real blast radius, not a specifier edit. It belongs in its own change
with its own live verification, and is left as a decision for the operator.

## Verified

- **1036 passed**, unchanged from before the upgrade.
- All six tier clients green through the real CLI on the new SDKs:
  `anthropic 1.5.0 | openai 3.13.0 | google-genai 1.69.0`.
- **Gemini specifically re-probed.** The upgrade pulled `h11` to 0.16.0, which
  `pip` flagged as conflicting with the installed `httpcore` 1.0.7 — the HTTP
  stack `google-genai` uses. Both Gemini tiers still authenticate and ping, so
  the warning is inert here, but it is the reason this was checked rather than
  assumed.
- Declared ranges checked against the installed versions programmatically;
  zero mismatches.

## Verified on Cloud Run — 2026-09-14

Confirmed in the deployed container: both Anthropic tiers and both OpenAI tiers
authenticate and ping. The AFC line under `gcp_gemini` confirms the image is on
google-genai 2.x, which is now declared rather than drifted into.

## Not done here

- The `h11`/`httpcore` resolver warning is pre-existing and unrelated to Event
  Mill's own declarations (as is a `tf2onnx`/`protobuf` conflict in the same
  venv). Neither is declared by this project.
- A ceiling bounds majors; it does not make the image and the dev venv
  identical, since both take the newest release in range. Exact parity needs a
  lock or constraints file — still an open decision.
- `Dockerfile.cloudrun` installs these through the extras, so the next image
  build picks the new majors up with no further change.
