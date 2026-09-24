# Plan: OpenAI native PDF input (Stage 3, documents)

**Status:** steps 1–5 built and step 6 run on the probe PDF, 2026-09-24
(`docs/change_log/2026-09-24-openai-anthropic-native-pdf.md`); D1–D4 decided
there. Outstanding: the 91-page live rerun. Written 2026-09-24, after the provider-scoped
capability fix (`docs/change_log/2026-09-24-provider-scoped-native-check.md`).
Parent plan: `docs/specs/multi_provider_llm_clients.md`, Stage 3 ("Outstanding:
... documents (`input_file` plus the dispatcher-side byte materialisation)").

## Goal

`threat_intel_ingester` and `threat_report_analyzer`, pinned to OpenAI with
`use`, read a PDF natively: page text **and** page images, the way they do on
Gemini. The alternative is only what pypdf can extract. It is done when:

1. An OpenAI-pinned run of both tools on the probe PDF uses the native path,
   and the ingester recovers 82/82 non-technique indicators (the Gemini
   baseline from `scripts/make_probe_pdf.py`).
2. The 91-page report from the 09-24 run completes natively on OpenAI, with
   the plan sized from OpenAI's own measured limits.
3. No PDF is ever stored at OpenAI (see D1).
4. Every figure in `openai.json` `file_handling` is either measured or cited
   from the provider's documentation, and labelled as one or the other.

## What exists today

| Piece | State |
|---|---|
| `OpenAIClient.query_text` | Done; Responses API, `store=False`, `reasoning.effort`, usage parsing, error classification |
| `OpenAIClient.query_with_document` | Stub returning `bad_request` |
| `openai.json` capabilities | No `native_pdf`, so the dispatcher refuses before calling the client (correct today) |
| `openai.json` `file_handling` | **Placeholders**: 100 pages / 32 MB / 1500 tokens per page, `preferred_ingestion: files_api`. Marked unverified |
| `DocumentPart` | Has `storage_uri`, `file_path` and `inline_bytes`; no one fills `inline_bytes` |
| Dispatcher PDF guard | Already reads the **routed** provider's `max_pages` / `max_size_mb` |
| Plan sizing and capability check | Provider-scoped as of 09-24, via `supports_native_document` and the new `LLMQueryInterface.output_limits()`. That one method replaces the parent spec's proposed `output_budget()` / `max_output_tokens()` pair, so the cap and the reserve always come from the same provider |
| Anthropic | Same stub, but its manifest *does* declare `native_pdf`; see D2 |

## What OpenAI documents

From `developers.openai.com/api/docs/guides/pdf-files`, read 2026-09-24:

- The content part is `{"type": "input_file", ...}` with one of `file_data`
  (`"data:application/pdf;base64,..."`, which requires `filename`), `file_id`
  (Files API, `purpose: "user_data"`) or `file_url`.
- The model gets **both the extracted text and an image of each page**. Page
  images need a vision-capable model.
- `detail`: `"low"`, `"high"` or `"auto"` sets page-image fidelity and
  therefore cost.
- **Each file must be under 50 MB, and so must the total across all files in a
  request.** The placeholder's 32 MB is wrong.
- **No page limit and no per-page token cost is stated.** Both have to be
  measured. Don't copy them from another vendor; the placeholders appear to
  be Anthropic's figures.

## Decisions for the operator

**D1 — Inline bytes only, or also the Files API?**
The client sends `store=False` on every request as a declared no-retention
property, because this platform handles incident data. A Files API upload is
stored at OpenAI until deleted. That undoes the property, and cleaning up
depends on a delete that can fail.
*Recommendation:* inline `file_data` only. Remove `files_api` from
`ingestion_paths` and set `preferred_ingestion: inline_bytes`. The cost is that
base64 adds about 33% to the request, so the effective ceiling is about
37 MB of PDF inside the 50 MB request. That still covers every report so far.

**D2 — What about Anthropic, which has the same stub?**
The 09-24 fix makes the capability check honest for OpenAI, but an
Anthropic-pinned run still plans native batches that the client refuses.
Options:
- (a) Build Anthropic's document path in this same stage. Byte
  materialisation, which is most of the work, is shared, and Anthropic's
  `document` block is a small addition.
- (b) Take `native_pdf` off `anthropic.json` until Stage 4. This is simple,
  but the manifest then misstates the model.
- (c) Add a client-level declaration of which ingestion paths the client
  *implements*, checked alongside the manifest capability. It is honest and
  general, but it is new vocabulary.

*Recommendation:* (a). It removes the gap rather than recording it, and (c)
becomes unnecessary once no stub is left.

**D3 — Mapping `media_resolution` to `detail`.**
*Recommendation:* `low→"low"`, `medium→"auto"`, `high→"high"`. Record in the
manifest what "auto" actually costs, once it's measured. The ingester's default
is medium.

**D4 — Should OpenAI get its own latency model?**
`LatencyModel` is global, calibrated on Gemini, and already known to be 6–8×
pessimistic there (memory: ingester latency model). OpenAI's speed on 10-page
PDF batches is unknown.
*Recommendation:* record timings in the live runs and decide afterwards. Don't
add a per-provider latency model before there is data.

## Steps

**1. Byte materialisation (dispatcher; shared with Anthropic).**
- Add `DocumentPart.read_bytes()`: `inline_bytes` if set, else read
  `file_path`, else fetch `storage_uri` through `framework/cloud/resolver.py`.
  Otherwise fail with a named error. Never return partial bytes.
- The dispatcher fills `inline_bytes` before `client.query_with_document`
  when the routed tier doesn't declare a new `remote_uri_gs` capability.
  Add that token to both Gemini tiers only, so Gemini's zero-copy path is
  unchanged. Register it in `docs/specs/reserved_vocabulary.md`.
- Cloud Run artifacts from the same session already resolve to a local
  `file_path` (confirmed 09-20). The GCS fetch covers only artifacts from
  another session or another instance.
- Tests: bytes come from each source in order; Gemini still gets the URI;
  a missing file yields a named failure and never an empty document.

**2. `OpenAIClient.query_with_document`.**
- The request is `input=[{"role": "user", "content": [input_file, input_text]}]`
  plus `instructions=system_context`. Reuse `query_text`'s `reasoning.effort`
  mapping, `max_output_tokens`, `store=False` and response parsing. Don't
  build a second parser.
- `input_file` = `{"type": "input_file", "filename": <basename>,
  "file_data": "data:application/pdf;base64,<b64>", "detail": <D3>}`.
- Set `transport_path="inline_bytes"`.
- Classify errors: an over-size or over-page 400 becomes a distinct
  `error_kind` with a message naming the limit, so the ingester's
  failure log says why. Timeouts reuse the existing classification.
- Tests with the SDK mocked: the exact request shape; `store=False` present;
  base64 round-trips; `files.create` is never called (the D1 tripwire); a
  truncated reply is flagged the same way as on the text path.

**3. Measure the provider (live, both tiers).**
- Page cost: run the probe PDF at each `detail` and read `input_tokens` from
  usage, less a text-only baseline, then divide by pages. Write the result to
  `tokens_per_page_by_resolution` with `_verified` notes.
- Page ceiling: binary-search page counts with a generated PDF until the
  provider refuses. Record the error text. If nothing refuses below the
  context window, record that the context window is the limit.
- Size: confirm the 50 MB request ceiling against base64 overhead with one
  over-limit request.
- Only then add `native_pdf` to both tiers and set `document_strategies`
  `application/pdf` to `native`. **The capability goes in last.** The
  09-24 fix means the plugins start planning native the moment it appears.

**4. Anthropic's document path (if D2 = a).**
- Use the same materialisation, the Messages API `document` block with a
  base64 source, and the same measurements against `anthropic.json`'s
  placeholders.

**5. Guardrail test across all manifests.**
- For every provider manifest, every tier declaring `native_pdf` must map to a
  client whose `query_with_document` does not return the "not implemented"
  failure. This would have caught the Anthropic gap, and it stops the next
  vendor from shipping a capability flag ahead of its client.

**6. Live runs and record.**
- On both tools, both tiers, the probe PDF and the 91-page report, record:
  - recall against ground truth;
  - `[PLAN]` against the actual batches;
  - per-call latency, which is the input to D4;
  - truncations;
  - token usage.
- Compare with the Gemini baseline. Write a dated change log entry with the
  numbers, including anything that did not work.

## Risks

- **Reasoning tokens and large PDFs against the 180 s deadline.** A 10-page
  batch at medium effort may exceed the deadline on OpenAI where Gemini
  doesn't. The plan sizes batches from the latency model, which has never
  seen OpenAI, so step 6 may force D4.
- **Page images cost tokens.** Inputs will be much larger than on the text
  path. `detail="low"` is the escape hatch, but it may lose small print; see
  the probe recall.
- **Model output is untrusted shape** (memory). Expect the first live runs to
  surface defects that scripted tests can't. Budget for a second pass.

## Out of scope

- `query_multimodal` for OpenAI. Nothing calls it.
- `file_url` ingestion. Sending OpenAI a URL means handing it a fetchable link
  to incident data.
- Changing Gemini's path in any way beyond the `remote_uri_gs` token.
