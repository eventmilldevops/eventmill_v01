# 2026-09-24 — Native PDF on OpenAI and Anthropic, sent inline

Stage 3 (documents) from `docs/specs/openai_document_path_plan.md`, built the
same day as the provider-scoped check that exposed the gap. Both report tools
now read PDFs natively when the operator runs them on OpenAI or Anthropic.
Before this, those runs fell back to text extraction on every page.

## Decisions (operator, 09-24)

| | Decision |
|---|---|
| D1 | **Inline only, both vendors.** No Files API: an upload is retained provider-side until deleted, which would undo `store=false` for incident data |
| D2 | **Anthropic in the same stage.** Its manifest declared `native_pdf` while its client refused every document |
| D3 | `media_resolution` → OpenAI `detail`: `low→low`, `medium→auto`, `high→high` |
| D4 | No per-provider latency model yet; timings recorded below |

## Changes

- **`DocumentPart.read_bytes()`** reads inline bytes, then the local file,
  then `gs://` (through `GCSStorageBackend`). It raises `DocumentUnavailable`
  rather than returning empty or partial bytes, because an empty document
  comes back from a model as a confident answer about nothing. Clients pass
  `allow_remote=False`: fetching from storage is the framework's job.
- **The dispatcher reads the bytes** before calling any client whose tier
  lacks the new **`remote_uri_gs`** token, which only Gemini declares.
  Gemini's zero-copy path is unchanged. An unreadable document is refused
  before any call is made.
- **`OpenAIClient.query_with_document`** sends one user turn:
  `input_file` (base64 `file_data`, `filename`, `detail`) plus
  `input_text`, with `store=False`, `instructions` and `reasoning.effort`.
- **`AnthropicClient.query_with_document`** sends a base64 `document`
  block plus a text block. Anthropic has no equivalent of `detail`.
- Both clients now use a shared **`_send`** for text and documents, so a
  document reply is checked for failure, filtering, refusal and truncation
  by exactly the same code as a text reply.
- **Manifests.** `native_pdf` added to both OpenAI tiers (last, after
  measurement). Every PDF figure is now measured or cited, and each
  manifest's `_verified` note says which:

| | OpenAI | Anthropic | Gemini (unchanged) |
|---|---|---|---|
| tokens / page | **605** measured (was 1500) | **2407** measured (was 1500) | 560 |
| `detail` effect | none on a text-only page (603 / 605 / 605) | n/a | — |
| max_pages | **600**, largest verified; no refusal found below the 400k context (~660) | **250**, largest verified; 1M context binds ~415 | 1000 |
| max_size_mb | **50** documented, applies to the file (40 MB file = 53 MB base64 accepted) | **24** measured: the documented 32 MB **includes base64**, so 20 MB passed and 25 MB was refused twice | 50 |

- Anthropic reports an oversized request as a **dropped connection**, which
  the client classifies as `transient`. The dispatcher's size guard is what
  stops such documents; don't raise `max_size_mb` without re-measuring.
- **Guardrail test:** every provider whose manifest declares `native_pdf`
  must have a client that does not refuse a document. It fails on the old
  Anthropic stub (checked by swapping it back in).
- `docs/specs/reserved_vocabulary.md` gains the provider capability tokens.
- `AGENTS.md`, `CLAUDE.md` and both plugin READMEs quoted "100 pages / 32 MB"
  as fact; they now give the measured figures or point at the manifests.

## Live results (probe PDF, 3 pages, 94 indicators)

Wired like the shell: all three providers bound to one dispatcher, and the
operator's choice on the wrapper. That reproduces the 09-24 setup where Gemini
was bound alongside.

`threat_intel_ingester`, whole-document plan (one run each; **see the
correction in `2026-09-24-untrusted-shape-crash.md`**: OpenAI's false-positive
judgement on this probe varies from run to run, down to rejecting all 74):

| Provider (light) | Plan | Native calls | Time | Non-technique | Techniques |
|---|---|---|---|---|---|
| OpenAI gpt-5.6-terra | native, cap 83,712 | 1 | 58 s | 62/82 | 12/12 |
| Anthropic claude-sonnet-5 | native, cap 83,712 | 1 | 80–95 s | 62/82 | 12/12 |
| Gemini gemini-3.8-flash | native, cap 36,864 | 1 | 89 s | 62/82 | 12/12 |

**The 20 missing are the probe's domains, and no provider was ever sent
them:** the regex stage produced no domain candidates (`candidates_by_type`
has none). That is the same on every provider and predates this work. It is
not the RFC 2606 "model declines test data" effect the probe script warns
about, which would show up as rejections. **Worth a separate look.**

`threat_report_analyzer` summarise, heavy tier: gpt-5.6-sol and claude-opus-5
each made one native call, `inline_bytes`, ok.

### Page-range batching (forced with `EVENTMILL_NATIVE_S_PER_PAGE=60`)

Three single-page batches on each provider. Every sub-PDF was cut, read and
sent inline, and every call succeeded. Both runs ended `partial` because of one
metadata disagreement between batches, which the merge records by design.

**One behavioural finding, reproduced twice:** batched on OpenAI, the model
marked **56 of 65** refined indicators as false positives (non-technique
recall 6/82). Anthropic, batched the same way, kept all 62. Every OpenAI call
parsed cleanly (9, 30 and 26 refined IOCs), so this is the model's judgement,
not the transport. The probe uses RFC 5737 documentation addresses and
reserved TLDs. Seen one page at a time, without page 1's report framing,
gpt-5.6-terra calls them test data; given the whole document, it doesn't.
Real reports carry real indicators, so this may be a probe artifact. But it
means **batch context affects OpenAI's false-positive rate**, and the 91-page
rerun should be checked for it: compare `candidates_rejected` against a
Gemini run of the same report.

### Timings (input to D4)

| | Batch | Seconds |
|---|---|---|
| OpenAI | p1 / p2 / p3 | 35 / 26 / 44 |
| Anthropic | p1 / p2 / p3 | 17 / 28 / 41 |

The latency model estimated 262 s for all three together; the actual totals
were 105 s and 86 s. That matches the Gemini finding (model pessimistic), so
no per-provider model yet.

## Checked

- 22 new tests (`tests/framework/test_document_inline_bytes.py`): byte
  sources in order, empty and missing files refused, clients never fetch
  from storage, the dispatcher materialises or leaves the URI by capability,
  the exact request shape of both clients, `store=False`, the `detail`
  mapping, truncation flagged as on text, and a tripwire on Files API upload
  for each vendor.
- Six existing tests encoded the placeholder figures (100 pages, 32 MB,
  1500 tokens). They now read the manifests and keep their intent: the
  guard reads the routed provider, and the providers differ.
- Gemini-like fixtures in `test_llm_dispatcher.py` and
  `test_provider_seam.py` now declare `remote_uri_gs`, as the real manifest
  does.
- Full suite **1864 → 1886 passed, 1 skipped** (Gemini's entry in the
  guardrail, which has its own document tests).
- `ruff` isn't installed here; new code lines were checked by hand against
  88 characters.

**Not yet run:** the 91-page report from the original run, on Cloud Run.
Live-run harnesses are in the session scratchpad, not the repo.
