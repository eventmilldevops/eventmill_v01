# Change Log — Threat Intel Persistence & Large Report Intake
**Date:** 2026-04-12  
**Session Duration:** ~12 hours  
**Primary File Modified:** `plugins/threat_modeling/threat_report_analyzer/tool.py`  
**Supporting Files:** `docs/specs/manifest_schema.json`, `cloud_install/provision-gcp-project.sh`, `pyproject.toml`

---

## Overview

Two independent but related capability areas were implemented in sequence during this session:

1. **Persistent Summary Storage** — LLM-generated summaries were previously ephemeral (in-memory only). The session implemented a predictable, cross-tool-accessible file-based storage convention using the common bucket.

2. **Large Report Intake & Chunking Pipeline** — The original summarizer silently truncated reports at 50 KB, which meant most real-world threat intelligence PDFs (e.g. Dragos, CrowdStrike, Mandiant annual reports at 50–300 pages) were summarized with dramatically incomplete context. This was replaced with a full chunking pipeline supporting up to 50 MB / 1000-page PDFs.

---

## Part 1 — Persistent Summary Storage

### Problem Statement

Before this session the `_summarize_report` method used an LLM to generate a markdown summary and returned it in a `ToolResult`. Once the calling session ended, the summary was gone. Every subsequent invocation would re-run the LLM call on the same report, consuming tokens and time unnecessarily.

Beyond simple caching, there was a deeper architectural need: Event Mill is designed as a multi-tool pipeline. A threat report summary produced by `threat_report_analyzer` is directly useful input for:

- `risk_assessment_analyzer` — needs threat context to score controls
- `attack_path_visualizer` — needs techniques to plot graph edges
- Future `log_investigator` tools — need actor/technique context to triage alerts

Without persistent storage, each downstream tool would either need to re-invoke `threat_report_analyzer` or accept the summary as a manually passed parameter. Neither is appropriate for an agentic pipeline. The solution is a shared, predictable file-system location that any tool in the platform can scan and read independently.

---

### Change 1.1 — `GENERATED_BASE` Constant in `tool.py`

**File:** `plugins/threat_modeling/threat_report_analyzer/tool.py`

```python
GENERATED_BASE = "generated"
```

**Reasoning:** A string constant was used rather than a hardcoded literal because the generated directory name must be consistent across all path-building helpers (`_get_generated_path`, `_summary_output_path`, `_scan_directory`). Any future rename needs to happen in exactly one place. The name `"generated"` was chosen as the most semantically clear and neutral term — it distinguishes tool-produced artifacts from source data without implying a specific output type (not `"summaries"`, not `"output"`, since the convention must generalize to other tools producing non-summary artifacts).

---

### Change 1.2 — `_get_generated_path()` and `_summary_output_path()` Helpers

**File:** `plugins/threat_modeling/threat_report_analyzer/tool.py`

```python
def _get_generated_path(self, context: Any) -> Path | None:
    common_path = self._get_common_bucket_path(context)
    if common_path is None:
        return None
    generated = common_path / self.GENERATED_BASE / "threat_report_analyzer"
    generated.mkdir(parents=True, exist_ok=True)
    return generated

def _summary_output_path(self, report_relative_path: str, context: Any) -> Path | None:
    generated = self._get_generated_path(context)
    if generated is None:
        return None
    normalized = report_relative_path.replace("\\", "/")
    output = generated / (normalized + ".summary.md")
    output.parent.mkdir(parents=True, exist_ok=True)
    return output
```

**Reasoning:** The storage path convention `common/generated/{tool_name}/{source_relative_path}.summary.md` was deliberately chosen to mirror the source report's path structure. This accomplishes two things:

1. A human (or tool) looking at the bucket can immediately determine which summary corresponds to which source report without needing a lookup table or database query.
2. Because the tool name is embedded as a subfolder (`threat_report_analyzer/`), other tools producing different artifact types can use the same `generated/` root without namespace collision. For example, a future `log_investigator` tool would write to `generated/log_investigator/`.

The helpers eagerly create intermediate directories via `mkdir(parents=True, exist_ok=True)`. This is intentional — the tool should not fail on first run simply because the directory hasn't been seeded yet. The provisioning script seeds the top-level path, but deeper paths (e.g. `generated/threat_report_analyzer/vendor_advisories/`) are created on demand.

---

### Change 1.3 — `_scan_directory()` Skips `generated/`

**File:** `plugins/threat_modeling/threat_report_analyzer/tool.py`

```python
if parts[0] == self.GENERATED_BASE:
    continue
```

**Reasoning:** Without this guard, `list_reports` would enumerate previously generated `.summary.md` files alongside the source reports. This would be confusing at best (showing the same report twice) and incorrect at worst (summaries of summaries). Since the `generated/` prefix is deterministic and known, it can be excluded cleanly by checking the first path component of each discovered file.

This change was made to `_scan_directory` rather than at the caller level so that any future caller of `_scan_directory` automatically gets the correct behavior without needing to filter output.

---

### Change 1.4 — `_list_reports()` Annotates Reports with `has_summary`

**File:** `plugins/threat_modeling/threat_report_analyzer/tool.py`

```python
for report in reports:
    summary_path = self._summary_output_path(report["relative_path"], context)
    report["has_summary"] = summary_path is not None and summary_path.exists()
    if report["has_summary"]:
        common_path = self._get_common_bucket_path(context)
        if common_path:
            try:
                report["summary_relative_path"] = str(
                    summary_path.relative_to(common_path)
                ).replace("\\", "/")
            except ValueError:
                pass
```

**Reasoning:** The list action is the primary discovery mechanism for both the LLM orchestrator and downstream tools. By annotating each report with `has_summary: true/false` and, when available, the `summary_relative_path`, downstream tools can immediately know whether a pre-built summary exists and where to find it — without needing to call `summarize` first or maintain a separate registry.

This enables a practical optimization in multi-tool pipelines: a `risk_assessment_analyzer` that needs threat context can check `has_summary` from the report listing and consume the existing summary directly, bypassing the LLM call entirely.

---

### Change 1.5 — `_summarize_report()` Persists Output and Populates `output_artifacts`

**File:** `plugins/threat_modeling/threat_report_analyzer/tool.py`

The original method returned the summary only in the `ToolResult.result` dict. The change added a persistence block:

```python
summary_path = self._summary_output_path(report_path, context)
if summary_path:
    try:
        summary_path.write_text(summary_text, encoding="utf-8")
        ...
        output_artifacts = [{"artifact_type": "text", "file_path": str(summary_path), ...}]
    except Exception as e:
        logging.getLogger(...).warning("Failed to persist summary: %s", e)
```

**Reasoning:** The `output_artifacts` field in `ToolResult` is the mechanism by which the Event Mill framework registers generated files in the SQLite `artifacts` table (via `session/database.py`). Populating it ensures the summary is tracked at the session level — it can be queried, linked to the originating `tool_executions` row, and discovered by subsequent tools during the same session.

The persistence block is wrapped in a try/except deliberately. Summary generation (the LLM call) is the high-value operation; a failure to write the file to disk should not fail the entire tool execution and should not surface an error to the orchestrator. The warning log is sufficient for operator visibility.

---

### Change 1.6 — `summarize_for_llm()` Reports Storage Location

**File:** `plugins/threat_modeling/threat_report_analyzer/tool.py`

```python
stored = s.get("summary_path")
location = f" → {stored}" if stored else ""
return f"Summarized {s['report_path']} ({wc} words){location}"
```

**Reasoning:** `summarize_for_llm` is the compressed representation of a tool result shown to the LLM orchestrator in its context window. Including the storage path in this line means the orchestrator sees where the summary was persisted without needing to parse the full result dict. This is relevant when the orchestrator is composing a multi-step plan — knowing the path allows it to pass `summary_relative_path` directly to a downstream tool as an input artifact reference.

---

### Change 1.7 — `provision-gcp-project.sh` Seeds `generated/` Namespace

**File:** `cloud_install/provision-gcp-project.sh`

```bash
echo "   Initializing generated artifacts namespace in common bucket..."
init_common_folder "generated/threat_report_analyzer"
```

And in the Section 8 storage summary:
```bash
echo "   gs://${BUCKET_PREFIX}-common/generated/         (tool-generated artifacts)"
echo "   gs://${BUCKET_PREFIX}-common/generated/threat_report_analyzer/"
```

**Reasoning:** GCS does not have real directories — it uses object key prefixes. `init_common_folder` creates a zero-byte placeholder object (`.keep`) under the given prefix, which causes the path to appear in the GCS console and makes it discoverable via `gsutil ls`. Without this seeding step, operators provisioning a fresh project would see no `generated/` prefix in the bucket and might assume the convention wasn't set up correctly. The provisioning script is also the canonical documentation for what a fully initialized project looks like, so the Section 8 summary was updated to show the complete expected layout.

---

### Change 1.8 — `manifest_schema.json` — `description_long` and `chains_from`

**File:** `docs/specs/manifest_schema.json`

Two corrections were made:

1. **`description_llm` → `description_long`** — The `PluginManifest` class in `loader.py` reads `data.get("description_long", "")`. The schema had `description_llm` which would cause schema validation to reject valid manifests. This was a field name divergence between the implementation and the schema specification.

2. **Added `chains_from` property** — `PluginManifest` also reads `data.get("chains_from", [])` but the schema only defined `chains_to`. The `chains_from` property declares which other tools' outputs this tool can accept as input — it is the inverse of `chains_to`. Omitting it from the schema made manifests that declared `chains_from` fail JSON schema validation.

---

## Part 2 — Large Report Intake & Chunking Pipeline

### Problem Statement

The original `_summarize_report` implementation contained this line:

```python
content=content[:50000],  # Limit content size
```

This silently truncated every report to the first 50 KB of content before sending it to the LLM. For small reports (CISA KEV advisories, short actor profiles) this was acceptable. For real-world threat intelligence PDFs — Dragos OT Security Report (~120 pages), CrowdStrike Global Threat Report (~80 pages), Mandiant M-Trends (~130 pages) — the truncation meant the LLM was summarizing only the table of contents and first chapter. The output was structurally correct markdown but operationally misleading: key findings buried in later sections were silently omitted.

Additionally, the tool had no PDF support at all. `.pdf` was not in `SUPPORTED_EXTENSIONS`, and `_read_report_content` would attempt to read binary PDF data as UTF-8 text with `errors="replace"`, producing garbage content. Vendors publish the majority of their annual threat reports as PDFs.

The goal of Part 2 was to replace the truncation hack with a principled chunking pipeline while keeping all three actions (`list_reports`, `summarize`, `search_reports`) backward compatible.

---

### Change 2.1 — `Chunk` Dataclass

**File:** `plugins/threat_modeling/threat_report_analyzer/tool.py`

```python
@dataclass
class Chunk:
    index: int
    content: str
    token_estimate: int
    source_type: str
    page_start: int | None = None
    page_end: int | None = None
```

**Reasoning:** A dataclass was used rather than a plain dict to enforce the contract between the chunking helpers and the summarization loop. The `page_start`/`page_end` fields are optional because they only have meaning for PDF page-range chunks; text chunks produced by `_split_text_into_chunks` leave them as `None`. `source_type` (`"pdf_pages"` or `"text"`) allows downstream logging and artifact metadata to correctly describe the provenance of each chunk without needing to inspect the content.

The `token_estimate` is computed at chunk creation time rather than on demand to avoid re-scanning large content strings multiple times during the pipeline.

---

### Change 2.2 — Two New Prompt Templates

**File:** `plugins/threat_modeling/threat_report_analyzer/tool.py`

**`CHUNK_SUMMARIZATION_PROMPT_TEMPLATE`** — used per-chunk, targets 800–1500 words, includes a `{page_info}` slot that reads either `"pages 1–100"` or `"chunk 3"` depending on the source type. Structured output sections: Section Overview, Key Techniques, Threat Actors/Malware, Detection Opportunities, Key Mitigations.

**`SYNTHESIS_PROMPT_TEMPLATE`** — used for the second-pass synthesis across all chunk summaries. Targets the user-specified `max_words`. Explicitly instructs the model to deduplicate and normalize MITRE technique IDs across sections, and to identify cross-section threat patterns. Structured output: Executive Summary, Key Threat Patterns, ATT&CK Techniques (deduplicated), Detection Opportunities, Recommended Security Controls, Sources and References.

**Reasoning:** Two separate prompts were necessary because the cognitive task is different. Per-chunk summarization is extractive — find what's there. Synthesis is integrative — find patterns across the whole. Using the full synthesis prompt on a single chunk would produce a poorly structured output (e.g. an "Executive Summary" of 3 pages). Using the chunk prompt for the final synthesis pass would produce a collection of section-level summaries without the holistic intelligence assessment.

The existing `SUMMARIZATION_PROMPT_TEMPLATE` was retained unchanged. It is still used in legacy single-pass scenarios if they are re-introduced.

---

### Change 2.3 — `.pdf` Added to `SUPPORTED_EXTENSIONS`

**File:** `plugins/threat_modeling/threat_report_analyzer/tool.py`

```python
SUPPORTED_EXTENSIONS = {".json", ".pdf", ".xml", ".md", ".txt", ".csv", ".stix"}
```

**Reasoning:** Without `.pdf` in the set, `_scan_directory` would never return PDF files in `list_reports`, making PDFs invisible to the orchestrator. Adding it here is the single point of truth — `_scan_directory`, `_scan_local_reference_data`, and any future scanner that iterates over `SUPPORTED_EXTENSIONS` will automatically include PDFs.

---

### Change 2.4 — Intake Limit Constants

**File:** `plugins/threat_modeling/threat_report_analyzer/tool.py`

```python
MAX_PDF_SIZE_BYTES = 50 * 1024 * 1024   # 50 MB
MAX_PDF_PAGES = 1000
MAX_PAGES_PER_CHUNK = 100
MAX_TOKENS_PER_CHUNK = 100_000
MAX_TEXT_TOKENS_SINGLE_PASS = 150_000
CHARS_PER_TOKEN = 4
```

**Reasoning:** These limits were derived from the Gemini 2.5 Flash specifications cited in the design document:

- **50 MB / 1000 pages** — the stated maximum for PDF artifact processing in the Gemini 2.5 API. Enforcing this at intake prevents requests that would be rejected by the model API anyway, with a clearer error message than an API timeout.
- **100 pages per chunk** — at ~258 tokens/page, 100 pages ≈ 25,800 tokens, well under the 100k token per-chunk ceiling. This leaves headroom for the prompt template itself and the system prompt.
- **100k tokens per chunk** — chosen to keep each LLM call safely within one-tenth of the 1M token context window, preserving significant margin for the prompt, few-shot examples, and model overhead.
- **150k tokens for single-pass text** — for text files that fit within this limit, chunking adds overhead (multiple API calls, synthesis pass) with no benefit. The threshold allows most reasonably sized JSON/XML/Markdown reports to be handled in a single call while still protecting against truly large text dumps.
- **4 chars/token** — a standard approximation for English prose. More accurate tokenization would require a tokenizer library dependency; the approximation is sufficient for making chunking decisions where a ±20% error margin is acceptable.

Defining these as class constants rather than local variables or hardcoded literals means they appear in any future configuration layer, documentation auto-extraction, or override mechanism.

---

### Change 2.5 — `_summarize_report()` Rewritten with Chunking Pipeline

**File:** `plugins/threat_modeling/threat_report_analyzer/tool.py`

The method was completely rewritten. The pipeline has four phases:

**Phase 1 — Intake and chunk construction:**
```
PDF input → size check → _split_pdf_into_chunks() → list[Chunk]
Text input → token estimate → guard against >150k → _split_text_into_chunks() → list[Chunk]
```

For PDFs, if `pypdf` is unavailable or extraction fails, the method falls back to `_read_report_content` (which will also attempt pypdf and return `None` on failure), propagating a `PARSE_FAILED` error rather than silently generating a garbage summary.

For text files, if the input exceeds `MAX_TEXT_TOKENS_SINGLE_PASS`, the method returns `INPUT_TOO_LARGE` rather than truncating. This is a deliberate departure from the original behavior. Silent truncation produces confidently wrong summaries; an explicit error prompts the operator to provide a PDF or split the file upstream, which produces a correct summary.

**Phase 2 — Per-chunk summarization:**
```
for chunk in chunks:
    cs = _summarize_chunk(chunk, ...)    # one LLM call per chunk
    if multi-chunk: _write_chunk_artifact(cs, ...)   # persist intermediate
```

Each chunk is summarized independently. If a single chunk's LLM call fails, the exception is caught and logged; the chunk's raw content (first 3000 chars) is used as a fallback summary for that chunk. Processing continues for remaining chunks. This means a partially degraded LLM connection produces a partial report rather than a complete failure.

**Phase 3 — Synthesis:**
```
single chunk → final = chunk_summaries[0]["summary"]
multi chunk  → _synthesize_summaries(...) → second LLM pass
```

The synthesis pass is only invoked when more than one chunk was processed. For single-chunk reports this eliminates an unnecessary LLM call.

**Phase 4 — Persist final summary:**  
Identical to the original persistence logic from Part 1, now applied to the synthesized final output.

**Updated output schema:**
```json
{
  "action": "summarize",
  "summaries": [{
    "report_path": "...",
    "summary_path": "generated/threat_report_analyzer/...",
    "chunk_count": 5,
    "word_count": 1847,
    "summary": "...",
    "key_findings": [...],
    "relevant_techniques": [...]
  }],
  "artifacts_created": [
    "generated/threat_report_analyzer/report.pdf.chunk_000.summary.md",
    "generated/threat_report_analyzer/report.pdf.chunk_001.summary.md"
  ]
}
```

`chunk_count` was added to allow orchestrators and dashboards to distinguish single-pass reports from chunked ones without inspecting `artifacts_created`. `artifacts_created` provides the relative paths to all intermediate chunk artifacts for downstream tool consumption.

---

### Change 2.6 — Eight New Helper Methods

**File:** `plugins/threat_modeling/threat_report_analyzer/tool.py`

#### `estimate_tokens(text) → int`
Simple `len(text) // 4` with a floor of 1. Used at three points: deciding whether to chunk text input, computing chunk token estimates at creation, and logging before LLM calls. Keeping it as an instance method (rather than a module-level function) allows a future subclass to substitute a real tokenizer without changing any call sites.

#### `_resolve_report_path(report_path, context) → Path | None`
Extracts the path resolution logic that was previously duplicated between `_read_report_content` and inline code in `_summarize_report`. Given a path string, it tries:
1. Direct filesystem path (for `local_path` values from scan results)
2. Bucket-relative path joined to the common bucket root (for `relative_path` values like `"mitre/enterprise-attack.json"`)

Returns `None` if neither resolves. All callers now go through this single method, ensuring consistent behavior when the common bucket path is unavailable.

#### `_extract_pdf_text(file_path) → str | None`
Extracts all pages of a PDF as a single text string using `pypdf`. The `import pypdf` is placed inside the method body (guarded by try/except ImportError) so that the tool remains functional for text-format reports even if `pypdf` is not installed. This avoids a hard dependency at module import time and allows the tool to degrade gracefully — text reports work, PDFs emit a warning log.

Each page's `extract_text()` call is individually wrapped in a try/except so that a corrupted page does not abort extraction of the remaining pages; an empty string is substituted for any failed page.

#### `_split_pdf_into_chunks(file_path, max_pages_per_chunk) → list[Chunk]`
Reads the PDF with `pypdf`, caps the page count at `MAX_PDF_PAGES`, then slices into windows of `MAX_PAGES_PER_CHUNK` pages. Each window's text is joined with `"\n\n"` and wrapped in a `Chunk` with `page_start`/`page_end` set. The page numbers are 1-indexed to match how operators and the LLM describe page ranges in natural language.

The `max_pages_per_chunk` parameter is exposed (with a default of `None` → uses the class constant) to allow future callers to override the chunk size for specific use cases (e.g. a high-verbosity mode that uses 50-page chunks for higher per-section fidelity).

#### `_split_text_into_chunks(text, max_tokens) → list[Chunk]`
For text that exceeds `MAX_TOKENS_PER_CHUNK`, this method splits on `"\n\n"` paragraph boundaries, accumulating paragraphs into a chunk until the next paragraph would push it over the token limit. At that point the current chunk is flushed and a new one begins.

Paragraph-boundary splitting was chosen over character-boundary splitting because it preserves the logical structure of the content. An LLM summarizing a chunk that cuts mid-paragraph would produce awkwardly truncated context at the boundary. Cutting between paragraphs ensures each chunk is independently coherent.

The `max_tokens` parameter follows the same override convention as `max_pages_per_chunk`.

#### `_summarize_chunk(chunk, report_name, report_type, focus_areas, context) → dict`
Issues a single `query_text` call with `CHUNK_SUMMARIZATION_PROMPT_TEMPLATE`, targeting `max_tokens=2048`. Falls back to `chunk.content[:3000]` on any failure. Calls `_extract_techniques` on the LLM output to capture MITRE technique IDs from each chunk independently — these are later merged at synthesis time.

The 2048 output token limit was set to ensure the per-chunk summary is concise enough that the synthesis pass can comfortably fit all chunk summaries within its own context window. Ten 100-page chunks × 2048 tokens/chunk ≈ 20k tokens of chunk summaries — well within the synthesis prompt's budget.

#### `_synthesize_summaries(chunk_summaries, report_name, focus_areas, max_words, context) → str`
Formats all chunk summaries into a single block with section separators and labels (`[Pages 1–100]`, `[Pages 101–200]`, etc.) then issues a single `query_text` call with `SYNTHESIS_PROMPT_TEMPLATE` targeting `max_tokens=4096`. Falls back to the concatenated chunk summaries if the LLM call fails — this ensures a multi-chunk report always produces some output.

The section labels in the combined block give the synthesis model explicit provenance for each section's content, which improves its ability to attribute techniques and findings to specific parts of the original report.

#### `_write_chunk_artifact(chunk_summary, report_path, context) → dict | None`
Mirrors the structure of the final summary persistence from Part 1 but applied to per-chunk intermediates. Output path: `generated/threat_report_analyzer/{source_relative_path}.chunk_NNN.summary.md` (zero-padded chunk index for correct lexicographic sort order). Returns the full artifact descriptor dict including a `metadata` sub-object with `source_report`, `chunk_index`, `page_start`, `page_end`, and `extracted_techniques`. This metadata enables downstream tools to:
- Identify which source report a chunk came from
- Request specific page ranges for deeper analysis
- Skip re-summarizing chunks whose techniques have already been processed

---

### Change 2.7 — `_read_report_content()` Refactored

**File:** `plugins/threat_modeling/threat_report_analyzer/tool.py`

The original method (~25 lines) contained duplicated path resolution logic. It was reduced to ~11 lines by delegating path resolution to `_resolve_report_path` and PDF text extraction to `_extract_pdf_text`:

```python
def _read_report_content(self, report_path: str, context: Any) -> str | None:
    file_path = self._resolve_report_path(report_path, context)
    if file_path is None:
        return None
    if file_path.suffix.lower() == ".pdf":
        return self._extract_pdf_text(file_path)
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return None
```

This method is still used by `_search_reports` for content retrieval and by the PDF fallback path in `_summarize_report`. The refactor ensures PDF handling is consistent between both callers.

---

### Change 2.8 — `_search_reports()` Updated for PDF Content

**File:** `plugins/threat_modeling/threat_report_analyzer/tool.py`

The original method opened every file with `open(..., "r", encoding="utf-8", errors="replace")`. For PDFs this would return binary-decoded garbage, producing meaningless search matches. The fix:

```python
if local_path_obj.suffix.lower() == ".pdf":
    raw = self._extract_pdf_text(local_path_obj)
    content = raw.lower() if raw else ""
else:
    with open(local_file, "r", encoding="utf-8", errors="replace") as f:
        content = f.read().lower()

# Find matches   ← now applies to both PDF and text content
matches = []
for i, line in enumerate(content.split("\n"), 1):
    ...
```

The match-finding block was also corrected to sit outside the `else:` branch (it had been accidentally indented inside it during the initial edit), ensuring PDF content is actually searched after extraction.

---

### Change 2.9 — `summarize_for_llm()` Updated for Chunk Count

**File:** `plugins/threat_modeling/threat_report_analyzer/tool.py`

```python
chunks = s.get("chunk_count", 1)
chunk_info = f", {chunks} chunk(s)" if chunks > 1 else ""
return f"Summarized {s['report_path']} ({wc} words{chunk_info}){location}"
```

**Reasoning:** The LLM orchestrator uses `summarize_for_llm` output as a compact session history entry. Without chunk count, a 1000-page report summary and a 2-page advisory would produce identical-looking history entries. Including chunk count when > 1 gives the orchestrator a signal that the summarization involved a multi-pass pipeline and that intermediate chunk artifacts exist in `artifacts_created`.

---

### Change 2.10 — `pyproject.toml` — `plugins-threat-modeling` Extras Group

**File:** `pyproject.toml`

```toml
plugins-threat-modeling = [
    "pypdf>=4.0.0",
]
all = [
    "eventmill[dev,gcp,plugins-log-analysis,plugins-network-forensics,plugins-threat-modeling]",
]
```

**Reasoning:** `pypdf` is a C-extension-free pure-Python package so it has no platform-specific build requirements, but it is still an optional dependency — operators who only use the text-format threat reports do not need it. Defining it as an extras group follows the same pattern as `plugins-log-analysis` (which declared `pdfplumber` for the log analysis pillar). `pypdf>=4.0.0` is specified because the version 4.x series introduced a stable API for `PdfReader.pages[i].extract_text()` that is consistent across Python 3.11+.

The `all` group was updated so `pip install -e ".[all]"` continues to install every optional dependency for a full development environment.

---

## Files Changed Summary

| File | Change Type | Lines Affected |
|------|-------------|----------------|
| `plugins/threat_modeling/threat_report_analyzer/tool.py` | Major refactor + extension | +357 lines net |
| `docs/specs/manifest_schema.json` | Schema correction | 3 locations |
| `cloud_install/provision-gcp-project.sh` | Provisioning extension | 3 locations |
| `pyproject.toml` | New optional dependency group | +4 lines |

---

## Architecture Impact

The changes in this session establish two durable conventions for the Event Mill platform:

### Convention 1 — Generated Artifacts Namespace
```
{prefix}-common/generated/{tool_name}/{source_relative_path}.summary.md
```
Any tool that produces persistent artifacts should follow this pattern. It enables:
- Cross-tool discovery without a central registry
- Human-readable bucket browsing
- Idempotent re-generation (overwriting the same path)
- Chunk artifacts using the `.chunk_NNN.` infix pattern

### Convention 2 — Chunking Pipeline Interface
Tools processing large documents should:
1. Detect file type and size at intake
2. Reject inputs that exceed hard limits with an explicit error (not silent truncation)
3. Chunk large inputs into independently meaningful units
4. Summarize each chunk in a separate LLM call
5. Persist intermediate chunk artifacts with provenance metadata
6. Run a synthesis pass only when chunks > 1
7. Persist the final synthesis as the canonical summary artifact

This pipeline model is directly reusable by any future tool that needs to process large documents (log files, pcap reports, vulnerability databases).

---

*End of change log.*
