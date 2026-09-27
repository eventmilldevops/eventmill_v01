# Cloud Run summary artifact registered as "." — 2026-09-27

## What happened

On Cloud Run, `run threat_report_analyzer --action summarize` completed and
uploaded its summary to `gs://<common>/generated/threat_report_analyzer/...`,
but the output listing showed the artifact's path as `.`, and
`export <id>` failed with `[Errno 21] Is a directory: '.'`. Seen on the Dragos
2026 year-in-review PDF, on `gcp_gemini`.

## Cause

Two pieces of code that were each reasonable on their own:

- With no local bucket mirror (always the case on Cloud Run,
  `_get_common_bucket_path` returns `None` under `K_SERVICE`), the analyzer
  uploads the summary directly and returns an output descriptor carrying
  `gcs_uri` and **no `file_path`**.
- The shell registered each output descriptor via
  `Path(oa.get("file_path", ""))`. `Path("")` is `Path(".")`, and
  `Path(".").exists()` is true — so the working directory was registered as a
  `text/markdown` artifact. `show` and `export` then read a directory.

A side effect: because an artifact *was* registered, the shell's auto-persist
fallback did not run either, so nothing readable was kept for the session.

This is **not** from the 09-24 OpenAI/Anthropic PDF work (`bcd949c`). The shell
line dates from `d923c54` (09-05) and the analyzer's GCS branch from 09-15.
Local runs never reach the GCS branch, and no test exercised it.

## Change

- `framework/cli/shell.py`: an output descriptor with no `file_path` is
  skipped instead of registered as `.`.
- `threat_report_analyzer/tool.py`: on the no-mirror branch the summary is also
  written to `$EVENTMILL_WORKSPACE/artifacts/<report>.<stamp>.summary.md` — the
  ingester's existing convention — and the descriptor carries that `file_path`
  alongside `gcs_uri`. The local copy is written even if the upload fails, so a
  failed upload no longer loses the summary for the session. `summary_path` in
  the result still reports the `gs://` URI only when the upload succeeded.

Chunk summaries on the same branch still return `gcs_uri`-only descriptors;
with the shell fix they are simply not registered as session artifacts. They
remain in the bucket.

## Verified

- Two new tests in `tests/test_output_budget.py::TestSummaryWithoutLocalMirror`
  (upload succeeds; upload fails). Both fail on the previous analyzer code and
  pass now.
- Full suite: 1891 passed, 1 skipped.
- **Not run:** a Cloud Run redeploy and rerun. `ruff` is not installed in this
  environment, so lint was not run.
