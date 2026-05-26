# Change Log — Tiered LLM Routing, PDF Normalization & CLI Improvements
**Date:** 2026-04-12  
**Primary Files Modified:** `framework/llm/client.py`, `framework/cli/shell.py`, `plugins/threat_modeling/threat_report_analyzer/tool.py`  
**Supporting Files:** `cloud_install/Dockerfile.cloudrun`, `cloud_install/cloudbuild.yaml`, `cloud_install/docker-compose.cloudrun.yml`, `cloud_install/setup-deploy-server.sh`, `cloud_install/provision-gcp-project.sh`

---

## Overview

Three areas of work across this session:

1. **Tiered LLM routing** — `connect` (no args) now binds both Flash and Pro simultaneously; queries are routed to the correct model automatically based on output-token demand, with no user intervention required.
2. **Threat report analyzer quality fixes** — PDF text fragmentation normalization, GCS upload for generated summaries, and correct wiring of the user's `max_word_count` into the LLM prompt.
3. **CLI improvements** — Tool listing shows the exact invocation name; `help <tool_name>` renders the tool's README as plain text.

---

## Changes

### `framework/llm/client.py` — TieredLLMClient

**Added `TieredLLMClient`** — wraps two `MCPLLMClient` instances (light/Flash and heavy/Pro) and routes `query_text` and `query_multimodal` calls automatically:

- Routing threshold `LIGHT_THRESHOLD = 3500` output tokens.
- Requests ≤ 3500 → Flash (fast, cost-effective for bulk preprocessing).
- Requests > 3500 → Pro (analyst conversations, final summaries, synthesis).
- Graceful fallback: if the preferred tier is not connected, the other is used.
- `model_id` property returns a combined string (e.g., `gemini-2.5-flash + gemini-2.5-pro`) for logging compatibility.
- Implements the same `LLMQueryInterface` protocol as `MCPLLMClient` — plugins require zero changes.

**Routing in practice:**

| Caller | `max_tokens` | Routes to |
|--------|-------------|-----------|
| Chunk section summaries | 3072 | Flash |
| `ask` conversational queries | 4096 | Pro |
| Single-pass report summary | 8192 | Pro |
| Multi-chunk synthesis | 8192 | Pro |

---

### `framework/cli/shell.py` — Tiered Connect & Tool Help

**`connect` (no arguments):**
- Iterates all available models, creates an `MCPLLMClient` per model, connects each, and wraps them in `TieredLLMClient`.
- Reports success/failure per model. Prints routing threshold summary when both tiers are connected.
- `connect <model_id>` retains existing single-model behaviour.

**`models` command:**
- Adds a **Status** column showing `✓ connected` per model reflecting live connection state.
- `_model_connected_status()` helper handles both `MCPLLMClient` (single model) and `TieredLLMClient` (multi-model) correctly.
- Footer updated to document both `connect` forms and the routing threshold.

**`tools` command:**
- Adds **Invoke As** column showing `run <tool_name>` alongside the display name.
- Description column extended from 40 to 80 characters.

**`help <tool_name>`:**
- `do_help` overridden to intercept tool names.
- `_print_tool_help` reads the tool's `README.md` and passes it to `_render_markdown_plain`.
- `_render_markdown_plain` converts Markdown to readable terminal plain text: H1/H2/H3 headings with underlines, code blocks indented 4 spaces, table separator rows stripped, word-wrapped paragraphs at 78 chars.

---

### `plugins/threat_modeling/threat_report_analyzer/tool.py` — Summary Quality & Persistence

**PDF text normalization (`_normalize_pdf_text`):**
- New static method applied to all `pypdf` extraction paths (`_extract_pdf_text` and `_split_pdf_into_chunks`).
- Detects word-per-line fragmentation: blocks where average line length < 30 chars are reassembled into readable prose.
- Handles hyphenated line breaks (`word-\nword` → `wordword`), strips standalone page numbers, preserves bullets and numbered lists.
- Resolves the root cause of poor LLM summaries from complex PDFs (composite fonts, multi-column layout).

**`max_word_count` wiring:**
- `_summarize_chunk` gains `max_words: int | None` parameter.
- Single-chunk reports pass `max_words` and use `SUMMARIZATION_PROMPT_TEMPLATE` (which includes `{max_words}`) instead of the section chunk template.
- Output token budget scaled: `max(2048, min(8192, max_words × 8))` — prevents LLM truncation on large word-count requests.
- Chunk `out_tokens` raised from 2048 → 3072, giving headroom for the 800–1500 word target in `CHUNK_SUMMARIZATION_PROMPT_TEMPLATE`.

**GCS persistence for generated summaries (`_upload_to_gcs`):**
- New helper uploads UTF-8 text to the common GCS bucket using `google-cloud-storage`.
- Resolves project from `GCP_PROJECT_ID` with fallback to `GOOGLE_CLOUD_PROJECT`.
- `_summarize_report`: when `_summary_output_path()` returns `None` (Cloud Run / no local mirror), final summary is uploaded to `generated/threat_report_analyzer/<report_path>.summary.md`. Previously the summary was generated in memory and silently discarded.
- `_write_chunk_artifact`: when `_get_generated_path()` returns `None`, chunk summaries are uploaded to GCS with a `gcs_uri` field in the artifact descriptor. Previously returned `None` immediately.
- Local write path: `summary_path.parent.mkdir(parents=True, exist_ok=True)` added before writing, fixing silent failures when intermediate subdirectories did not exist.

---

### `cloud_install/` — GCP Deployment Fixes

| File | Change |
|------|--------|
| `Dockerfile.cloudrun` | Added `plugins-threat-modeling` extras to pip install |
| `cloudbuild.yaml` | Added `--set-secrets`, `--memory 1Gi`, `--service-account`, `EVENTMILL_BUCKET_PREFIX` substitution |
| `docker-compose.cloudrun.yml` | Corrected credentials mount; added `GEMINI_FLASH_API_KEY`, `GEMINI_PRO_API_KEY`, `EVENTMILL_BUCKET_PREFIX`, `GOOGLE_CLOUD_PROJECT` |
| `setup-deploy-server.sh` | Added `EVENTMILL_BUCKET_PREFIX` to deploy env template; corrected `GCS_LOG_BUCKET` |
| `provision-gcp-project.sh` | Added `logging.googleapis.com` to enabled APIs list |

---

## Verification

The `threat_report_analyzer` summarize action was confirmed working end-to-end:
- PDF text extracted and normalized into readable prose.
- LLM (Pro via tiered routing) produced structured markdown summaries at the requested word count.
- Output saved to GCS and confirmed accessible.
- Test outputs reviewed for both Waterfall Security and Dragos 2026 OT threat reports.
