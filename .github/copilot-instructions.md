# Event Mill Copilot Instructions

Read `AGENTS.md` before changing code. It is the operational briefing; consult
`CLAUDE.md` for framework invariants and navigation to the normative specs.
Make a dated entry in `docs/change_log/` for significant changes.

## Commands

Run commands from the repository root. Python 3.11+ is required (the container
uses 3.12). On Windows, prefix commands that print checkmark/cross characters
with `PYTHONIOENCODING=utf-8`.

```bash
pip install -e ".[all]"

pytest
pytest tests/framework/test_llm_dispatcher.py
pytest tests/framework/test_llm_dispatcher.py::TestRoutingPrecedence
pytest -k "clamp"

ruff check .
black .
mypy framework plugins

python scripts/validate_schemas.py
python scripts/generate_tool_catalog.py
python -m framework.cli.shell
```

For a plugin change, run its contract tests directly, for example:

```bash
python -m pytest plugins/log_analysis/log_navigator/tests/ -v
```

`python scripts/validate_manifests.py` is useful when changing manifests, but
currently fails for a pre-existing schema mismatch: 15 manifests use
`stability: "stable"`, while the schema permits `experimental`, `verified`,
`core`, or `deprecated`. Do not widen the schema or remap those values without
an explicit behavior decision.

## Architecture

Event Mill is an investigation CLI, deployed as a ttyd browser terminal on
Cloud Run. The request path is:

```text
CLI shell -> session/artifact state -> deterministic router -> plugin executor
-> plugin (optional LLM query) -> ToolResult + compressed summary
```

- `framework/cli/shell.py` is the composition root and interactive command
  surface. It coordinates SQLite-backed investigation sessions, artifact
  registration, plugin discovery and execution, routing, cloud resolution, and
  LLM clients.
- `framework/routing/` keeps the complete plugin catalog out of LLM context.
  It deterministically selects a pillar, scores candidate tools using
  configured rules and session state, and recommends tool chains. Do not add
  LLM calls to routing.
- `framework/plugins/` loads tools dynamically from each manifest, provides a
  read-only `ExecutionContext`, applies manifest timeouts, and records the
  concise `summarize_for_llm()` output used for follow-on reasoning.
- `framework/artifacts/` and `framework/session/` track immutable artifacts
  and investigation state. Locally they use the workspace filesystem and
  SQLite; with `K_SERVICE` set, `framework/cloud/resolver.py` switches
  artifact resolution to GCS and logging to Cloud Logging JSON.
- `framework/llm/` owns Gemini connectivity, tier routing, output clamping,
  native document dispatch, and retired-model fallback. Plugins access it only
  through `ExecutionContext.llm_query`.
- `plugins/<pillar>/<tool_name>/` contains self-describing investigation tools.
  The active pillars are log analysis, network forensics, and threat modeling;
  other pillar directories may be present without registered tools.

## Plugin Contract

Plugins are structural rather than inheritance-based. A plugin directory needs
`manifest.json`, `tool.py`, `schemas/input.schema.json`,
`schemas/output.schema.json`, examples, a README, and contract tests. The
loader imports each tool with the flat module name
`eventmill_plugin_<pillar>_<tool>`, so avoid package-relative assumptions.

- The manifest's `pillar` must match its parent directory. Its fields drive
  discovery, routing, timeouts, model defaults, and tool chaining. Adding a
  manifest field requires matching changes in both
  `framework/plugins/loader.py` and
  `docs/specs/manifest_schema.json`, whose additional properties are rejected.
- Match the result dataclasses and import style already used by the target
  plugin. Most plugins deliberately define local `ToolResult` and
  `ValidationResult`; do not normalize them to framework imports.
- Implement `metadata()`, side-effect-free `validate_inputs()`, `execute()`,
  and `summarize_for_llm()`. Use standard `ErrorCodes` and keep summaries under
  2,000 characters (prefer the actionable 500-1,000-character range).
- Treat `ExecutionContext` as read-only. Plugins do not call other plugins or
  mutate framework state; register produced files only through
  `context.register_artifact()`.
- Use `context.llm_query.query_with_document()` for supported document
  artifacts. It selects GCS URI, inline native ingestion, or a clear fallback;
  do not duplicate that transport logic in a plugin.

The normative contract is `docs/specs/tool_plugin_spec.md`; see
`docs/guides/plugin_development.md` for a complete plugin example.

## LLM Invariants

`framework/llm/providers/gcp_gemini.json` is the sole source of model IDs,
token limits, native-file capabilities, and PDF token costs. Do not hardcode
these values elsewhere.

- Tier precedence is per-call `QueryHints.tier`, then manifest `model_tier`,
  then `light`. `QueryHints(tier=None)` leaves the manifest default intact.
- Light and heavy have identical input/output capacities. A tier is a
  reasoning-depth and cost choice, never a payload-size choice.
- For bulk extraction, request `thinking_level="low"` deliberately; the
  provider default is `medium`. Treat `LLMResponse.truncated` as an incomplete
  answer even when `ok` is true.
- PDF page cost depends on `media_resolution` (`low`, `medium`, `high`), not a
  fixed constant. Do not use Gemini's deprecated `temperature`, `top_p`, or
  `top_k` controls, and use `models.generate_content()` rather than the
  Interactions API.

## Deployment and Repository Conventions

Before modifying `cloud_install/`, read `AGENTS.md` and
`cloud_install/README.md`. `GOOGLE_CLOUD_PROJECT`, `CLOUD_RUN_REGION`, and
`EVENTMILL_BUCKET_PREFIX` have no safe defaults. Keep tenant configuration in
`~/.eventmill/deploy.env`, never in the repository.

Provisioning scripts own IAM writes; deployment scripts only verify them. Keep
the repository-root-derived build context, use `gcloud storage` rather than
`gsutil`, and use explicit error handling rather than silent `set -e` failures
in bootstrap scripts. Run `bash -n` on changed shell scripts.

Do not add or remove code comments unless requested; match the density and
style of the surrounding code. Plugin-only dependencies belong in their
per-pillar `pyproject.toml` extras, so framework code must not require one.
