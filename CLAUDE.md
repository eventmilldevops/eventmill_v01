# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Read AGENTS.md first

`AGENTS.md` is the operational briefing and is **not duplicated here**. It covers
cloud deployment (the mandatory region/bucket variables, the four `actAs`
delegations, operator IAM roles, the `testIamPermissions` debugging method, the
Google geo-block on some hosting IPs) and the LLM model facts that have already
caused bugs. This file covers architecture and the invariants that make a change
correct or incorrect.

## Commands

```bash
pip install -e ".[all]"                  # dev + gcp + all plugin extras

pytest                                   # testpaths = tests/ and plugins/
pytest tests/framework/test_llm_dispatcher.py            # one file
pytest tests/framework/test_llm_dispatcher.py::TestRoutingPrecedence   # one class
pytest -k "clamp"                        # by name
pytest -q tests/ plugins/                # what CI-equivalent runs look like

ruff check .                             # line-length 88, rules E,F,I,N,W,UP
black .                                  # line-length 88
mypy framework plugins                   # ignore_missing_imports = true

python scripts/validate_manifests.py     # plugin manifests vs docs/specs/manifest_schema.json
python scripts/validate_schemas.py       # input/output JSON schemas
python scripts/generate_tool_catalog.py  # regenerate the tool catalog

python -m framework.cli.shell            # run the shell (or the `eventmill` script)
```

On Windows, prefix with `PYTHONIOENCODING=utf-8` — several scripts print ✓/✗ and
will crash on cp1252 otherwise.

**`validate_manifests.py` currently exits non-zero with 15 errors**, all
`'stable' is not one of ['experimental','verified','core','deprecated']`. This is
pre-existing: 15 of 16 manifests declare a `stability` value the schema does not
define. Because `stability` governs visibility and auto-invoke policy, remapping
it is a behaviour decision, not a typo fix — do not widen the enum to silence it.
Nothing in the build or deploy path runs the validator.

## Architecture

Three layers, described in `docs/specs/framework_architecture.md`:

- **`framework/`** — CLI shell (`framework/cli/shell.py`, ~2350 lines, the entry point and
  the place most wiring lives), session state in SQLite, LLM dispatch, artifact
  registry, plugin loader/executor, cloud abstraction.
- **`plugins/<pillar>/<tool_name>/`** — self-describing analysis tools.
- **`framework/routing/`** — decides which plugins are visible to the LLM at any
  point, so the full tool catalog never enters the prompt. Four-phase model:
  pillar selection → candidates → weighted scoring → chain recommendations. It is
  **entirely deterministic**; the router makes no LLM calls.

### The plugin contract is structural, not inheritance-based

A plugin is a directory with `manifest.json`, `tool.py`, `schemas/`, and usually
`examples/` and `tests/`. `PluginLoader` reads the manifest, imports the entry
point under a **flat module name** (`eventmill_plugin_<pillar>_<tool>`) to avoid
parent-package lookups, and pulls out the class the manifest names.

Nothing is subclassed. `EventMillToolProtocol` is a `typing.Protocol`, and **14 of
16 plugins define their own local `ToolResult` / `ValidationResult` dataclasses**
rather than importing the framework's. That is deliberate isolation, not
duplication to be refactored away. Only plugins needing `QueryHints` or
`ArtifactRef` (`threat_intel_ingester`, `threat_report_analyzer`) import from
`framework.plugins.protocol`. When editing a plugin, match the convention already
in that file rather than normalizing it.

The manifest drives routing, discovery, timeouts, and model tier. Adding a field
means updating `PluginManifest.__init__` in `framework/plugins/loader.py` **and**
`docs/specs/manifest_schema.json`, which sets `additionalProperties: false` — an
unregistered field fails validation for every plugin at once.

`summarize_for_llm()` is the context-compression mechanism and is capped at 2000
characters by `PluginExecutor` (which truncates rather than failing). Keep it well
under that; it is what downstream reasoning actually sees.

Plugins receive a read-only `ExecutionContext`. The one write they may perform is
`context.register_artifact()`.

### LLM tier selection

Tier precedence, in order: **per-call `QueryHints` > manifest `model_tier` >
`max_tokens > 3500` heuristic.** The heuristic is a last resort for
framework-level callers only; plugins should never rely on it.

`TierScopedLLMClient` wraps the shared dispatcher once per plugin execution and
supplies the manifest's tier when a call passes no hints — so the common case
needs no code in the plugin. `LLMDispatcher` stays plugin-agnostic.

`framework/llm/providers/gcp_gemini.json` is the **single source of truth** for
model ids, token limits, per-tier capabilities and PDF page cost. Do not hardcode
any of those elsewhere; `framework/llm/backends/gemini.py` reads it rather than repeating it.

The two tiers are **capacity-identical** (1,048,576 in / 65,536 out). Tier means
reasoning depth and cost, never how much fits — any logic that picks a tier from
data size is wrong by construction. See AGENTS.md for the rest, including why PDF
page cost is not a constant.

### Local vs Cloud Run

The runtime detects Cloud Run via the `K_SERVICE` env var and switches artifact
resolution to GCS and logging to JSON for Cloud Logging. `framework/cloud/resolver.py`
resolves buckets per pillar plus a shared `common` bucket, and is
region-independent. An empty `EVENTMILL_BUCKET_PREFIX` makes it fall back to a
literal string and read buckets that do not exist — the service starts cleanly
and is silently wrong, which is why the deploy scripts guard it.

## Conventions

- **Do not add or remove comments unless asked.** Match the surrounding density.
- Shell scripts: run `bash -n` before committing. Prefer explicit error handling
  over `set -e` in anything long-running or bootstrap-related — a silent abort
  under `set -e` is what motivated the `cloud_install` rewrite.
- Never commit tenant identifiers, secrets, or credentials. Deploy configuration
  belongs in `~/.eventmill/deploy.env`.
- Check imports before assuming a library is available; plugin dependencies live
  in per-pillar extras in `pyproject.toml`, not the base install.
- Significant changes get a dated entry in `docs/change_log/`.

## Where to look

| Question | File |
|---|---|
| Plugin contract, error codes, timeout classes | `framework/plugins/protocol.py` |
| Manifest fields and validation | `framework/plugins/loader.py`, `docs/specs/manifest_schema.json` |
| Tier routing, clamping, fallback | `framework/llm/client.py` |
| Model facts | `framework/llm/providers/gcp_gemini.json` |
| Normative plugin spec | `docs/specs/tool_plugin_spec.md` |
| How to write a plugin | `docs/guides/plugin_development.md` |
| Why the LLM layer looks like this | `docs/specs/llm-dispatcher-native-document-handling.md` |
| What changed and why | `docs/change_log/` |
