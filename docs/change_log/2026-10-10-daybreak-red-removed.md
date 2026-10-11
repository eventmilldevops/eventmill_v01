# 2026-10-10 — Daybreak Red removed; start-up warnings for non-plugin directories

Two small changes found while the operator was live-testing the logging
compliance tools.

## Daybreak Red removed

Operator decision: `openai_daybreak_red` can go. `openai_daybreak_blue` stays
registered, by the operator's choice when asked, and so does the Daybreak key
and secret wiring it reads.

- Deleted `framework/llm/providers/openai_daybreak_red.json`.
- Removed its entries from `PROVIDER_CLIENTS`, `PROVIDER_SECRETS` and
  `PROVIDER_SDK_INSTALL` in `framework/llm/factory.py`.
- Removed it from every default provider list: `.env.example`,
  `cloud_install/cloudbuild.yaml`, `deploy-cloudrun-secrets.sh` (default list,
  the typo guard's accepted ids and its error text), `deploy-cloudrun.sh`,
  `docker-compose.cloudrun.yml`, `setup-deploy-server.sh`,
  `cloud_install/README.md`.
- Tests that used Red as the example of a second OpenAI-backed provider now use
  Blue (`test_provider_vendor_identity.py`, `test_provider_registry.py`,
  `test_llm_dispatcher.py`). The test that the two colours were different
  models became a test that the Daybreak model is not a standard OpenAI model.
- `AGENTS.md`, the projector run schema's `vendor` description, and two specs
  updated where they described the present. Earlier change log entries and
  Stage 7 of `multi_provider_llm_clients.md` are left as written.

**Consequence for an existing configuration.** `openai_daybreak_red` is now an
unknown provider id. An `EVENTMILL_LLM_PROVIDERS` that still names it is
refused by `deploy-cloudrun-secrets.sh`, and at run time
`configured_providers` raises `UnknownProviderError`. The built-in defaults no
longer name it, so only an explicit setting is affected: a `deploy.env`, a
Cloud Build `_LLM_PROVIDERS` substitution, or a local `.env`.

Not changed: the Secret Manager secret, `OPENAI_DAYBREAK_API_KEY`,
`EVENTMILL_MOUNT_DAYBREAK`. Blue still reads them. Blue's manifest is still
unverified and has never been called; with the Daybreak key set it will still
bind and show in the banner.

## Start-up warnings for `examples` and `postures`

`PluginLoader.discover_all` warned "Plugin directory X missing manifest.json"
for every directory in a pillar without a manifest. Two such directories are
not plugins: `plugins/network_forensics/postures/` (posture overrides) and
`plugins/log_analysis/examples/` (the sample corpus added in `4c39744`). On
Cloud Run both warnings were printed above the banner.

- The loader now warns only when the directory has a `tool.py`, which is what
  marks a directory someone meant to be a plugin. Anything else is logged at
  debug level.
- `scripts/validate_schemas.py` skips the same directories; it had reported
  `examples: schemas/ directory not found`.

## Verified

- `pytest -q tests/ plugins/`: 2059 passed, 1 skipped (was 2063: five
  Red-parametrised cases gone, one added). The new test covers the loader (a `postures` directory is silent, a
  directory with `tool.py` and no manifest still warns).
- `python scripts/validate_schemas.py`: 40 schemas, all valid, no error for
  `examples`.
- Local discovery of the real `plugins/` tree: 20 plugins, neither warning.

## Not verified

- Nothing was deployed. The edits to the `cloud_install` scripts were checked
  with `bash -n` only.
- The banner on Cloud Run after this change has not been seen.
