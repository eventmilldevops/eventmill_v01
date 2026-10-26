# 2026-10-26 — `threat_intel_ingester --url`: fetch a report and read it in one pass

Asked for by the operator: give the ingester a URL in the console and have the
report ingested, with no manual download and `load`.

## The change

- **`--url` on `threat_intel_ingester`**, as an alternative to `--artifact_id`
  (exactly one of the two; the input schema says so with `anyOf` + `not`).
  The fetched document is registered as an artifact of its own, so `artifacts`
  lists it, `export --all` carries it, and a re-run by `--artifact_id` reads
  the same bytes rather than a page that may have changed.
- **`framework/documents/url_fetch.py`** fetches exactly one document:
  http/https on default ports, no credentials in the URL; every resolved
  address must be public (private, loopback, link-local/metadata, CGNAT,
  multicast, reserved, and IPv4 embedded in IPv6 are refused); the connection
  is pinned to the checked address with TLS verified against the hostname
  (httpx `sni_hostname`), so a second DNS answer cannot redirect it; each
  redirect is re-checked, at most 5; 10 MB for pages, 50 MB for PDFs, 90 s
  overall, counted after decompression; proxy environment variables ignored.
  What came back is classified by its bytes first (`%PDF-`), then its header.
- **`framework/documents/web_markdown.py`** converts a page to Markdown with
  escaping **off** and link targets dropped (text kept), keeps tables as rows
  and code fenced, drops scripts, navigation, footers and related-post cards,
  and splits the result at headings.
- **`plan_text_ingestion`** in `framework/documents/profile.py`: the PDF
  planner's arithmetic over sections instead of pages — `text_whole` when the
  reply fits one call, else `text_batched` on section boundaries, labelled
  `s1-4`. `plan_ingestion` shares the batching code and is unchanged in
  behaviour (its reason strings and `to_dict` output are identical).
- **The ingester's sectioned-text path** sits beside the native PDF block, not
  inside it: the native path's output budget and thinking level, a truncated
  batch halved and re-run, a failed one handed to the chunked path. Results
  share `native_batch_results` and its provenance, so the merge and
  supersession needed no change.
- A fetched **PDF** is registered as `pdf_report` with `mime_type`, `pages` and
  `size_bytes`, as `load` would, and goes the native path unchanged.
- **Provenance:** `report_metadata.source` and the persisted artifact's `source`
  carry the URL as given and as served, redirects, fetch time, SHA-256 of the
  fetched bytes and of the Markdown, and the address that answered. Prompts
  carry `[Fetched from <url>]`. `coverage_unit` gains `sections`; timings gain
  `fetch_s` and `text_s`.
- Manifest: `external_connectivity: true`; `markdownify>=1.2.0,<2.0.0` and
  `httpx>=0.27.0,<1.0.0` added to the manifest and to the
  `plugins-log-analysis` extra (which the Cloud Run image already installs).

## Why it was the right call

**Markdown, not PDF rendering and not letting the model fetch.** A provider's
own URL tool leaves no copy of what was read, so the result cannot be traced
or re-run, the prompt is no longer byte-identical across providers, and each
vendor needs its own code. Printing a page to PDF needs a headless browser in
the image, pays per page however little text a page holds, splits tables at
page breaks, and inherits the providers' page caps. Markdown keeps the table
rows, costs what the text costs, and has no page limit.

**Escaping off is the load-bearing detail.** Checked on the operator's sample,
the Microsoft Storm-0940 post: a stock converter wrote `144.172.64\[.\]99`, and
the ingester's own IP regex returned `[]` for it. Every defanged indicator in
the IOC table would have been invisible to the regex baseline. markdownify
also escapes `_` by default, which breaks `evil_domain[.]com` the same way.

**One pass is what fixes the operator's sample.** Their 17-page PDF run of the
same report was split in two: batch 2 named the actor "Unknown", three
confidence conflicts made the run `partial`, the same attack path appeared
twice, and T1199 and T1555.006 — both in the article's own ATT&CK list — were
missing. Loaded text would have been worse: 6,000-character chunks at 4,096
output tokens make that ~38 KB article about seven calls. The sectioned path
sends it whole.

**`<article>` is not trusted.** On that page the four `<article>` elements are
related-post cards for *other* campaigns (Storm-2990, Storm-3119); the post is
in `<main>`. Picking the largest `<article>` returned 533 characters of
teasers. The root is now whichever of `<article>`/`<main>` holds the most text,
and small nested cards are removed.

**The per-page latency term is dropped for sections.** It was calibrated on PDF
page images (12 s each). Charged per section, it would split a 30-section blog
post that fits one call by an order of magnitude — the over-splitting
AGENTS.md already records for PDFs, made worse.

**Existing inputs are untouched.** A loaded `.md` or `.html` file still goes
through the 6,000-character chunked path; only an artifact carrying
`ingest_as: markdown_sections` (written by `--url`) takes the new one. A test
holds that.

## Verified

- Live, local, against the operator's URL, through `ThreatIntelIngester.execute`
  with a recording stand-in for the LLM: fetched over the pinned connection
  (TLS verified against the hostname), 31,296 characters in 30 sections,
  **16 candidates** — the 6 IOC-table IPs refanged and the 10 ATT&CK ids
  including T1199 and T1555.006 — and **no** vendor-domain or "Run query" URL
  candidates. Plan `text_whole`, ~3,180 of 36,864 output tokens: **one call**,
  `max_tokens=65536`, thinking `medium`. The related-post teasers did not reach
  the prompt.
- New tests: `tests/framework/test_url_fetch.py` (address policy, URL shape,
  every-answer resolution, pinning, redirects, size caps streamed and
  declared, classification, error reporting), `tests/framework/test_web_markdown.py`
  (verbatim indicators, structure, noise, content root, sections),
  `TestTextPlan` in `test_document_profile.py`, and
  `plugins/.../tests/test_url_ingestion.py` (one call, sizing, provenance,
  registration, heading batches, truncation halving, chunked fallback, linked
  PDF, refusals, re-run by artifact id, and the loaded-Markdown regression).
  `test_input_schema_has_required` was rewritten for the new contract.
- Full suite on Python 3.10 (the only interpreter available) with every extra
  installed: **2,170 passed, 5 failed**. The 5 need 3.11 and none touches a
  changed file — `tomllib` (2 provider-registry tests) and
  `datetime.fromisoformat` nanosecond parsing (3 `log_compliance_auditor`
  tests). Neither file imports anything this change touches.
- Live, through the real shell (`EventMillShell.onecmd`) with no LLM bound:
  `--url` parsed from flags, the shell's help reads "one of artifact_id, url",
  `http://169.254.169.254/...` refused with "link-local address (the cloud
  metadata range)", and the operator's URL produced a regex-baseline result
  with the fetched Markdown listed by `artifacts` beside the output.
- `validate_schemas.py`: 40 valid. `validate_manifests.py`: the ingester
  validates; the run's pre-existing errors are unchanged.

## Not verified

- **No live LLM call.** The one-pass prompt has not been answered by a real
  model, so extraction quality on the sample is still a claim, not a
  measurement. The first live run should compare its actors, conflicts and
  techniques against the operator's 17-page PDF run.
- The sectioned latency model is uncalibrated; it borrows the native base and
  per-candidate terms (and their `EVENTMILL_NATIVE_*` overrides).
- Cloud Run: no build or deploy. The image picks the new dependencies up from
  the extra it already installs.
- Python 3.11/3.12; `ruff`, `black`, `mypy` (not installed here).

## Decision left open

`safe_for_auto_invoke` stays `true`. Nothing lets a model start a tool today
(Gemini's AFC is disabled and no plugin passes tools), so the flag governs
nothing yet. If that changes, a URL read out of a report could be fetched on
the report author's say-so; the spec's guidance for tools with external
effects is `false`, and that is an operator's call, not this change's.
