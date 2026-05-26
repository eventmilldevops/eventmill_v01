# Change Log — LLM Timeout Fixes, DAG Visualizer & Cloud Run Stability
**Date:** 2026-04-13  
**Primary Files Modified:** `framework/llm/client.py`, `framework/cli/shell.py`, `framework/plugins/protocol.py`, `plugins/threat_modeling/attack_path_visualizer/tool.py`, `plugins/log_analysis/threat_intel_ingester/tool.py`  
**Supporting Files:** `cloud_install/Dockerfile.cloudrun`, `cloud_install/deploy-cloudrun.sh`, `cloud_install/deploy-cloudrun-secrets.sh`, `plugins/log_analysis/threat_intel_ingester/manifest.json`, `plugins/log_analysis/threat_intel_ingester/tests/test_contract.py`

---

## Overview

Five areas of corrective work across this session, all driven by production instability introduced during the April 12 integration sprint:

1. **LLM connection timeouts** — GenAI SDK calls could hang indefinitely; HTTP timeout and retry-on-timeout logic added.
2. **Plugin execution timeout enforcement** — `shell.py` called `execute()` directly, bypassing the `PluginExecutor` timeout mechanism; thread-based timeout with visible progress ticker added.
3. **Attack path DAG rendering** — `_render_ascii_dag()` rendered each path sequentially instead of as a unified graph; rewritten with topological layering.
4. **Cloud Run session stability** — WebSocket drops during LLM calls caused by OOM kills (512 Mi), missing ttyd keepalive, and missing session affinity.
5. **Gemini Pro misrouting** — `threat_intel_ingester` requested 4096 `max_tokens`, routing it to Pro instead of Flash; reduced to 3000.

---

## Changes

### `framework/llm/client.py` — HTTP Timeout & Retry Expansion

**Problem:** `genai.Client` was initialized without an HTTP timeout. Long-running LLM calls (especially during Gemini API congestion) could hang indefinitely, appearing as tool timeouts to the user.

**Fix:**
- Added `http_options={"timeout": 120_000}` (120 seconds) to `genai.Client()` initialization, preventing individual API calls from hanging beyond 2 minutes.
- Expanded `_is_retriable()` to include timeout-related exception markers: `"DeadlineExceeded"`, `"Timeout"`, `"timed out"`. These were previously not caught by the retry loop, causing timeout errors to immediately propagate as fatal failures instead of being retried.

**Impact:** LLM calls that hit transient timeouts are now retried (up to 3 times with exponential backoff) instead of failing immediately.

---

### `framework/cli/shell.py` — Thread-Based Timeout Enforcement with Progress Ticker

**Problem:** `do_run()` called `instance.execute()` directly on the main thread with no timeout enforcement. The `PluginExecutor` class existed with timeout support, but was not wired into the shell. Tools could run indefinitely.

**Fix:**
- Added `threading` import and `TimeoutClass` import.
- Wrapped `instance.execute()` in a daemon thread with `thread.join(timeout=limit)`.
- Added a **10-second polling ticker** that prints elapsed time (`⏳ 30s / 120s ...`) instead of a single silent `join()`. This serves three purposes:
  1. Gives the user visible progress feedback.
  2. Sends periodic output through the WebSocket, preventing Cloud Run's load balancer from treating the connection as idle.
  3. Enforces the timeout — if the thread is still alive after the limit, execution is recorded as failed and the shell returns to the prompt.
- On timeout, the execution is marked `FAILED` with a descriptive summary and logged via `log_user_activity`.

**Impact:** All tools now respect their manifest `timeout_class` limit. Users see real-time progress and get clean timeout messages instead of indefinite hangs.

---

### `framework/plugins/protocol.py` — TimeoutClass Alias Alignment

**Problem:** Plugin manifests use `"short"` and `"long"` for `timeout_class`, but `TimeoutClass.LIMITS` only defined `"fast"`, `"medium"`, `"slow"`. Any manifest with `"short"` or `"long"` silently fell back to the `"medium"` (120s) default — meaning fast tools got too much time and slow tools got too little.

**Fix:** Added `"short": 30` and `"long": 600` as aliases in `TimeoutClass.LIMITS`.

**Impact:** Manifest timeout values now map correctly: `short/fast` → 30s, `medium` → 120s, `long/slow` → 600s.

---

### `plugins/threat_modeling/attack_path_visualizer/tool.py` — Unified DAG Rendering

**Problem:** `_render_ascii_dag()` iterated over each path sequentially, printing techniques redundantly. Branch points and convergence points were annotated but not visually represented — the output looked like a list of linear paths, not a graph.

**Fix:**
- Added `_toposort_layers()` — Kahn's algorithm that assigns DAG nodes to topological layers. Nodes in the same layer (parallel branches) are grouped together.
- Rewrote `_render_ascii_dag()` to render a **unified graph topology**:
  - Each technique appears **exactly once**, regardless of how many paths include it.
  - Parallel nodes in the same layer are rendered **side-by-side** in columns.
  - Visual fork connectors (`┌──┴──┐`) for branch points and merge connectors (`└──┬──┘`) for convergence points are drawn between layers.
  - Entry, exit, branch, and convergence points are annotated with symbols (`▷`, `■`, `◇`, `◆`).
  - Path legend at top, symbol legend at bottom.
  - Unprotected stages warning preserved.

**Impact:** Multi-path attack graphs now display as a proper DAG with visual branching and convergence, matching the expected output topology.

---

### `plugins/log_analysis/threat_intel_ingester` — Gemini Pro Misrouting & Timeout

**Problem (routing):** The manifest declares `"model_tier": "light"` (Flash), but `tool.py` requested `max_tokens=4096`. The `TieredLLMClient` threshold is 3500 — so 4096 > 3500 routed every chunk to **Gemini Pro**, which was experiencing 503 UNAVAILABLE errors due to high demand. IOC JSON extraction does not need 4096 output tokens.

**Fix:** Reduced `max_tokens` from 4096 to 3000, keeping it below the Flash routing threshold.

**Problem (timeout):** The manifest declared `"timeout_class": "medium"` (120s), but the CrowdStrike report produces 43 chunks. At ~3-5s per LLM call (minimum), 43 calls need 130-215s — exceeding the 120s limit before accounting for any retries or 503 errors.

**Fix:** Changed `timeout_class` from `"medium"` to `"slow"` (600s).

**Impact:** Chunks now route to Flash (faster, no 503 congestion) with sufficient timeout budget for large reports.

---

### `plugins/log_analysis/threat_intel_ingester/tests/test_contract.py` — Dataclass Access Fixes

**Problem:** Multiple test classes used dict subscript syntax (`result["ok"]`, `result["error_code"]`) on `ToolResult` and `ValidationResult` dataclass objects, causing `TypeError: object is not subscriptable`. This was a latent bug from the v1.0 → v1.1 migration where return types changed from dicts to dataclasses.

**Fix:**
- Replaced all `result["ok"]` with `result.ok`, `result["errors"]` with `result.errors`, etc.
- Added `MockToolResult` dataclass with `ok`, `result`, `message`, and `output_artifacts` fields for `summarize_for_llm` tests.
- Added `example_tool_result` fixture that wraps the raw JSON example response into a `MockToolResult`.
- Updated `test_handles_error_result` to use `MockToolResult` instead of a plain dict.

**Impact:** All 43 threat_intel_ingester tests now pass. Full suite: 285 tests passing.

---

### `cloud_install/Dockerfile.cloudrun` — ttyd WebSocket Keepalive

**Problem:** Cloud Run's load balancer dropped WebSocket connections after ~60-90s of apparent inactivity during long LLM calls, disconnecting the analyst mid-execution.

**Fix:** Added `--ping-interval 30` to the ttyd command. This sends WebSocket ping frames every 30 seconds, preventing the load balancer from treating the connection as idle.

---

### `cloud_install/deploy-cloudrun.sh` & `deploy-cloudrun-secrets.sh` — Resource & Affinity Fixes

**Problem:** Containers were allocated 512 Mi memory. GCP Cloud Run logs confirmed OOM kills at 519-528 MB during PDF parsing + LLM prompt construction. Additionally, CPU was throttled outside active request processing (default Cloud Run behavior), starving the background Python thread during WebSocket sessions.

**Fix (both deploy scripts):**
- `--memory` increased from 512Mi → **2Gi**
- `--cpu` increased from 1 → **2**
- Added `--no-cpu-throttling` to prevent CPU starvation during WebSocket sessions
- Added `--session-affinity` to pin WebSocket connections to the same instance
- `--concurrency` reduced from 10 → 5 to prevent memory overcommit with larger per-session footprint

---

## Test Results

| Suite | Result |
|-------|--------|
| Full test suite | **285 passed** |
| threat_intel_ingester | 43 passed (was 17 passing, 1 failing) |
| attack_path_visualizer | 35 passed |
| Framework tests | All passing |

---

## Commits (chronological)

| Hash | Description |
|------|-------------|
| `4386f69` | fix: adding backoff retry to LLM queries |
| `2c03b6e` | fix: moved to DAG implementation for path visualization |
| `58d5fdf` | fix: changing LLM timeout to 2 mins, Gemini Pro can be slow on large inputs |
| `2a6bc6c` | fix: adding keep alive to resolve WebSocket short timeout and LLM long processing |
| `0313ffb` | fix: adding timer to LLM to see if it keeps WebSocket open |
| `1d0f930` | fix: Claude reverted the available RAM, doubled everything again |
| _(uncommitted)_ | fix: threat_intel_ingester routing to Flash, timeout to slow, test dataclass fixes |
