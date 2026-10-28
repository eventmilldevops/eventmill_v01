# 2026-10-27 — `anthropic_cyber`: the Anthropic CVP workspace key as its own provider

## Why

`adversary_path_projector` runs on `anthropic` were refused by Anthropic's cyber
safeguard: the response carried `stop_reason: refusal` and `category=cyber`, and
the projector surfaced it as `LLM_QUERY_FAILED`. That is a classifier decision,
not an authentication failure. The operator holds Cyber Verification Program
(CVP) status and created a separate API key in an approved CVP workspace. The
adjustment attaches to that workspace, not to the standard key, so the workspace
key needs to be a separately selectable provider, the same way Daybreak is.

## What changed

Same models as `anthropic` (`claude-sonnet-5-5` light, `claude-opus-5-5` heavy),
new provider id, new credential. No client code changed: `AnthropicClient`
already takes `provider_id` per instance.

- **`framework/llm/providers/anthropic_cyber.json`** — copy of `anthropic.json`
  with `provider_id: anthropic_cyber`, `api_key_env: ANTHROPIC_CYBER_API_KEY`
  on both tiers, and an UNVERIFIED notice in place of `_verified`. Limits,
  request constraints and PDF handling are inherited and not re-measured.
  Heavy falls back only to Sonnet on the same key, never to `anthropic`.
- **`framework/llm/factory.py`** — `PROVIDER_CLIENTS`, `PROVIDER_SECRETS`
  (`eventmill-anthropic-cyber`) and `PROVIDER_SDK_INSTALL` entries.
- **Display:** the tier labels read `Claude Sonnet 5.5 (CVP)` and `Claude Opus 5.5 (CVP)`
  in the startup model list and `models`, so the workspace models are not
  mistaken for the standard ones. `models` widens its name column to 24.
- **Config:** `.env.example`, `docker-compose.yml` (both services),
  `cloud_install/docker-compose.cloudrun.yml`.
- **Cloud Run:** `deploy-cloudrun-secrets.sh` (mount switch
  `EVENTMILL_MOUNT_ANTHROPIC_CYBER`, secret name override
  `EVENTMILL_SECRET_ANTHROPIC_CYBER`, incremental default provider list,
  typo guard arm, secret mount), `cloudbuild.yaml` (substitution, existence
  loop, `--set-secrets`, `_LLM_PROVIDERS`), `deploy-cloudrun.sh`,
  `deploy-cloudrun-api.sh`, `setup-deploy-server.sh`, `lab/lab-deploy.sh`
  (mount forced to 0), `provision-gcp-project.sh` and `provision-secrets.sh`
  (secret created as a placeholder until the workspace key is added).
- **Tests:** `test_provider_registry.py` (in `EVERY_PROVIDER`, expected tiers and
  key env, env scrub), `test_provider_vendor_identity.py` (new
  `TestCyberIsAnOrdinaryProvider`: keys never cross in either direction, a
  placeholder leaves every other provider available, the client stamps its own
  id through `with_model`), `test_llm_dispatcher.py` (inherits Anthropic's PDF
  page limit).

## Decisions

- **Provider id `anthropic_cyber`**, snake_case like every other id. It maps to a
  file name, an env-var token and shell `case` guards.
- **Secret `eventmill-anthropic-cyber`**, mounted to `ANTHROPIC_CYBER_API_KEY`.
  Its value must be an API key created inside an approved CVP workspace. A key
  from the standard workspace does not carry the classifier adjustment, so the
  provider would be refused the same way `anthropic` is.
- **Two tiers, not one.** Daybreak declares one model under both tiers so that
  `_fallback_client` cannot substitute a different model. Here the tiers really
  are Sonnet and Opus, so they stay separate and the same-key fallback is
  correct.
- **Vendor is `anthropic`.** Same lab, same models. A reader counting how far a
  finding's support extends must count vendors, so agreement between
  `anthropic` and `anthropic_cyber` is one model read twice, not two opinions.
  The group summary still counts provider ids; changing that is a separate
  decision recorded in `AGENTS.md`.

## Verification

- `tests/framework/test_provider_registry.py`,
  `test_provider_vendor_identity.py`, `test_llm_dispatcher.py`: 193 passed.
- Full suite, `pytest -q tests/ plugins/`: 2177 passed, 4 skipped.
- `bash -n` on every edited shell script; `cloudbuild.yaml` and the new
  manifest parse.
- `ruff check` on the touched Python: the two reported errors predate this
  change (`factory.py` line 243 quoted annotation, and the dispatcher test at
  line 473). mypy is not installed in this environment and was not run.

**Live result (operator-confirmed, 2026-10-27):** a projector run with
`use anthropic_cyber for adversary_path_projector` cleared the cyber refusal
that the same run on `anthropic` received. The operator confirmed this; the run
records were not reviewed here.

**Not yet verified:** `providers probe anthropic_cyber` has not been run, and
the limits and PDF handling are still inherited from `anthropic.json`. Until the
probe passes and the limits are measured, the manifest's UNVERIFIED notice
stands. Cloud Run has not been redeployed.

## Open

- If the workspace classifier still refuses the projector's content, the
  question goes to Anthropic through the CVP route. Prompt changes to get past
  the classifier are out of scope.
- Mythos access is not represented. Adding a Mythos model id is a manifest
  change once the id and limits are known.
