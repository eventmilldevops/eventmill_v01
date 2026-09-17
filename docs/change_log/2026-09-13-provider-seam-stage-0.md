# Change Log — Stage 0, pinning the provider seam

**Date:** 2026-09-13
**Primary Files Added:**
`docs/specs/multi_provider_llm_clients.md`,
`tests/framework/test_provider_seam.py`,
`tests/framework/test_probe_corpus.py`,
`scripts/make_probe_pdf.py`

Plan: `docs/specs/multi_provider_llm_clients.md`.

**No production code changed.** Stage 0 of the multi-provider work is entirely
tests and one committed fixture generator. Its purpose is to make Stage 1 — the
extraction of `GeminiClient` out of `framework/llm/client.py` — a refactor with a
definition of done rather than a judgement call.

**965 passed, 7 xfailed** (was 945 passed).

---

## Why a stage that changes no behaviour

The application requirement is that a second or third foundation model can be
used without changing the tools. The GPT 5.6 assessment proposed the right
decomposition for that — per-provider clients, a thin dispatcher, a small model-
client protocol, a registry keyed by `EVENTMILL_LLM_PROVIDER` — and its sequence
opens with "move the Google SDK code out of `MCPLLMClient` without changing
runtime behavior".

Roughly half of that code is not in `MCPLLMClient`. It is in `LLMDispatcher`,
and some of it reaches through the client interface into private attributes:

| What the dispatcher does today | Where |
|---|---|
| Builds Gemini `Part` objects from `client._genai_client` | `client.py:1167` `_execute_document_query`, a `@staticmethod` on the dispatcher |
| Calls `client._build_prompt(...)` on the document path | `client.py:981` |
| Calls `client._is_retriable(exc)` inside the document retry loop | `client.py:1249` |
| Constructs `MCPLLMClient` by name and clones four private attributes | `client.py:787` `_retry_on_retired_model` |
| Reads `pdf_handling()` / `tokens_per_pdf_page()` with no provider argument | `client.py:1022`, `:1053` |

`tests/framework/test_llm_dispatcher.py:36` was already recording this without
anyone reading it that way: its `FakeClient` has to implement `_build_prompt`,
because the dispatcher calls it. A fake that satisfies only the public interface
does not work today. That is the leak, stated as a test fixture.

So Stage 0 builds the instrument that makes the leak fail loudly, before anything
moves.

## `PublicOnlyClient` and the two groups

`tests/framework/test_provider_seam.py` introduces a fake that implements only
what the `LLMModelClient` protocol will declare — `provider_id`, `model_id`,
`tier`, `connected`, `total_tokens_used`, `connect`, `with_model`, `supports`,
and the three query methods. It deliberately has no `_genai_client`, no
`_build_prompt`, no `transport`, no `endpoint`.

**Group A — ten tests, passing today.** Text and multimodal queries, tier
precedence, output clamping, quota fallback to the other tier, the PDF
context-overflow guard, capability checks, and `connected_models()` all work
through the public interface unchanged. This is the genuinely provider-neutral
part of the dispatcher, and it is now pinned so a refactor cannot quietly take it
apart.

The PDF guard is in Group A on purpose. It is the one document-path decision that
is *not* the client's: refusing an oversized PDF is policy read from the manifest,
and it has to happen before any provider is asked to do work.

**Group B — seven tests, `xfail(strict=True)`.** The document path reaching the
client through its interface; grounding data arriving as an argument rather than
via a private method; the client choosing its own ingestion path from a
`DocumentPart`; the retired-model substitute being the same provider class and
carrying the session spend forward; and the dispatcher living at
`framework/llm/dispatcher.py` with no vendor SDK in its import tree.

`strict=True` is the mechanism that makes this stage worth anything. When Stage 1
lands, these start passing, strict xfail reports an unexpected pass as a
**failure**, and the markers have to be removed deliberately. Removing them is
Stage 1's definition of done.

Every Group B test also carries `raises=`, so it cannot fail for an unrelated
reason and go unnoticed. Verified under `--runxfail`, each fails at exactly the
coupling its `reason` names:

```
client.py:981  AttributeError: 'PublicOnlyClient' object has no attribute '_build_prompt'
client.py:789  AttributeError: 'PublicOnlyClient' object has no attribute 'transport'
               ModuleNotFoundError: No module named 'framework.llm.dispatcher'
```

One Group B-adjacent test asserts the *defect* rather than the requirement —
`test_the_current_dispatcher_module_does_import_one`, which confirms `client.py`
imports `google`. It exists so the two module-invariant xfails cannot both be
passing for a trivial reason, and it is deleted with the markers in Stage 1. It
says so in its own docstring.

### The SDK-blocking test the plan asked for does not work

The plan specified importing the dispatcher with `google` and `google.genai`
blocked from `sys.modules`. That is not a valid instrument here: `client.py`
wraps its import in `try/except ImportError` and sets `_HAS_GENAI = False`, so a
blocked SDK leaves the module importing cleanly. The test would have passed today,
against a module that imports Google at line 29.

Replaced with an `ast` walk over the module's import statements, asserting no
import names `google`, `openai` or `anthropic` at its root. It is precise about
what is forbidden, and it tolerates a comment or string mentioning a vendor — the
dispatcher keeps `gs://` handling and will keep talking about it.

## The probe corpus

`make_probe_pdf.py` was the instrument that made the 2026-09-12 Flash comparison
mean something: a synthetic report whose indicator inventory is *exact*, turning
"did the two models agree" into "how much did each one find". `git log --all --
"*probe*"` is empty. It was never committed; only its output survives, in the
change log.

Rebuilt as `scripts/make_probe_pdf.py`, reproducing the recorded inventory: **94
unique indicators — 24 IPv4, 20 domain, 16 sha256, 12 URL, 10 CVE, 12
technique — 82 of them non-technique**, over three pages. The 12 URLs carry
hostnames that appear nowhere in the domain set, so a regex sweep finds more
candidates than there are indicators and the refinement stage has real
discrimination to do.

Three choices in it, none of them reconstructions — only the counts were
recorded, so the corpus itself is new:

- **No PDF dependency.** `fpdf2` lives in the network-forensics extra and
  `reportlab` is not a dependency at all. A fixture generator that runs only
  under one optional extra is one that stops being run, so the script writes the
  PDF itself — uncompressed Helvetica text, which is what the extraction path
  reads anyway. Verified readable by both `pypdf` and `pdfplumber`, with all 94
  indicators recovered from each.
- **Reserved names throughout** — RFC 5737 documentation addresses, RFC 2606
  reserved TLDs. Correct for a fixture committed to a security repository, and
  it costs something worth recording: a model may rank a `.invalid` host as
  obvious test data and decline to report it. That depresses absolute recall
  equally for every provider, so comparisons hold — but if a baseline run cannot
  reproduce 82/82 non-technique recall, this is the first knob to turn.
- **Technique names and tactics are read from the repo's own lookup**, not
  hardcoded. All 12 ids were checked against `mitre_techniques.json` and exist
  there; hardcoding their tactics would let the fixture drift away from the
  lookup the ingester reconciles against, and the v19 restructure is exactly the
  change that would make a hardcoded copy silently wrong. `T1078` is in the set
  deliberately — the 09-12 tactic-mismatch argument turned on it.

`tests/framework/test_probe_corpus.py` holds the generator to the baseline: the
counts, per-type uniqueness, the derived-hostname disjointness, technique
resolution against the lookup, three pages, every indicator surviving text
extraction, the corpus profiling as `ioc_dense`, and byte-identical output across
two runs. Extraction in the test uses `pypdf` rather than `pdfplumber` so it runs
without the log-analysis extra.

The page-overflow check is the one that matters most in practice: an indicator
written off the bottom of a page would be scored as a model miss in every
comparison afterwards.

## Not done here

- **No production code changed.** No rename, no extraction, no protocol.
- **The `stepstate-medium-2` run artifacts** are still not in the tree. Their
  numbers are recorded in `docs/change_log/2026-09-11-live-run-findings.md:158`
  and this stage does not change that.
- **No live run.** The probe generator is verified structurally — inventory,
  extraction, determinism — not against a model. The first live run is the one
  that confirms 82/82 is reproducible on this corpus, and it belongs with Stage 3
  or with a Gemini re-baseline, not here.
- `ruff` and `black` are not installed in this environment, as on 2026-09-12.
  Style matched by hand; the 88-character limit was checked directly.
- `validate_manifests.py` is untouched and still reports its pre-existing errors.
