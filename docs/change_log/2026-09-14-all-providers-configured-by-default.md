# Change Log — every deployment configures all three providers

**Date:** 2026-09-14
**Primary Files Modified:** `cloud_install/deploy-cloudrun-secrets.sh`,
`cloud_install/cloudbuild.yaml`, `cloud_install/deploy-cloudrun.sh`,
`cloud_install/docker-compose.cloudrun.yml`,
`cloud_install/setup-deploy-server.sh`, `cloud_install/Dockerfile.cloudrun`,
`cloud_install/README.md`, `framework/llm/factory.py`,
`framework/cli/shell.py`, `.env.example`, `AGENTS.md`,
`tests/framework/test_provider_registry.py`

**1083 tests pass** (was 1080; +3). Operator decision, taken after
`EVENTMILL_LLM_PROVIDERS` being unset locally made three working vendor keys
bind nothing:

> Working infra remains a priority, field users will forget workarounds like
> setting variables.

---

## The asymmetry this rests on

| | Cost |
|---|---|
| Naming a provider whose key is absent | **None.** `build_clients` and `_discover_models` both skip a key that is unset or holds `placeholder`; the vendor is reported as dormant and the rest bind. |
| Not naming a provider whose key is present | **A vendor that never binds**, with no error — `models` omits it, `use` refuses it, and nothing says why. |

One of those has happened three times in this project. The other has not
happened at all, and cannot: the skip path is the same one every
placeholder-seeded deployment already exercises on every start.

So `EVENTMILL_LLM_PROVIDERS` now defaults to all three everywhere, and adoption
is decided by whether a key holds a real value — which is where the operator's
actual decision already lived.

## Changed

| Where | Was | Now |
|---|---|---|
| `cloudbuild.yaml` `_LLM_PROVIDERS` | `gcp_gemini` | all three |
| `deploy-cloudrun-secrets.sh` | `${…:-gcp_gemini}` | `${…:-gcp_gemini anthropic openai}` |
| `deploy-cloudrun.sh` | `${…:-gcp_gemini}` | all three |
| `docker-compose.cloudrun.yml` | `${…:-gcp_gemini}` | all three |
| `setup-deploy-server.sh` (generated `deploy.env`) | `export …="gcp_gemini"` | all three |
| `.env.example` | `gcp_gemini` | all three |
| `factory.configured_providers()` unset default | `(gcp_gemini,)` | `known_providers()` |

The code default moved too, so no layer disagrees with another. A container
started by hand, without the variable, now behaves like one the deploy scripts
launched.

## The deploy guard had to change with it, or this would have broken every deploy

`REQUIRED_SECRETS` was built **from** `LLM_PROVIDERS`: a placeholder in a
configured provider blocked Step 4 with `Deploy anyway? [y/N]`. That rule was
correct while the list meant "adopted". With all three always named it would
have fired on every deployment holding one vendor's key and not the other two
— the common case, and a perfectly healthy deployment. The field user this
change exists for would have met a scary prompt on their first deploy.

**Step 4 now tests values, not configuration:**

- ttyd's two secrets must be real, as before — a web terminal whose password is
  `placeholder` is an open door.
- **At least one** LLM secret must be real. That is the invariant worth keeping
  ("this deployment can do LLM work at all"), it names no vendor, and it
  survives a deployment that runs Anthropic and no Gemini.
- Everything else is reported: `·  s-anthropic holds 'placeholder' (dormant —
  will not bind)`.
- A deployer who cannot read secret values is **not** blocked. `secretAccessor`
  is a role the deploying human need not hold, and refusing on "cannot see"
  would block a good deploy over an IAM grant the service does not need.

Exercised against the script's own Step 4 text, extracted by line range so the
test runs the real code rather than a paraphrase:

| Scenario | Prompts? |
|---|---|
| Gemini keyed, other two placeholder (**the default field deploy**) | no |
| all three keyed | no |
| no LLM key at all | **yes** |
| ttyd still `placeholder` | **yes** |
| deployer cannot read secret values | no |

## Dormant had to become visible, not merely harmless

With every provider configured, a keyless vendor is expected — but "expected"
must not mean "silent". Before this, `_discover_models` skipped a placeholder
key and `connect` simply never mentioned that vendor again. A key that arrived
and a key that did not looked identical.

`connect` now ends with:

```
  ✓ Gemini 3.8 Flash (gemini-3.8-flash)
  ✓ Gemini 3.1 Pro (gemini-3.1-pro-preview)
  · anthropic: dormant — ANTHROPIC_API_KEY unset or placeholder
  · openai: dormant — OPENAI_API_KEY unset or placeholder
    Set a key and reconnect to bind one; no redeploy needed.
    'providers probe <id>' verifies a key before adopting it.
```

Two tests hold it: that a placeholder and an unset key are both named with
their env var while Gemini still binds, and that a fully-keyed session says
nothing extra.

## Docs corrected

`cloud_install/README.md` still said **"A mounted key is not yet a bound
provider. Model discovery currently reads `gcp_gemini.json` alone, so a real
Anthropic key reaches the container but does not appear in `models`. Confirm
delivery with `printenv`."** False since Stage A. `AGENTS.md` carried the same
claim against `shell.py:418`. Both now describe what happens: a real key binds,
a placeholder is skipped and named, `providers` is the diagnostic.

`AGENTS.md` also keeps the warning that mattered — do not make a per-provider
placeholder blocking again — now with the reason it would be wrong rather than
merely annoying.

## Verified

- **1083 passed**, none skipped, none xfailed.
- `bash -n` clean on all five `cloud_install` shell scripts; both YAML files
  parse and `_LLM_PROVIDERS` reads back as `gcp_gemini anthropic openai`.
- Step 4 exercised across the five scenarios above.
- Locally, with the variable unset entirely and only Gemini keyed: two binds,
  two dormant lines naming their env vars.
- `ruff` / `black` / `mypy` are not installed in this venv, so none was run.

## What an operator still has to do

Adopting a vendor on Cloud Run is unchanged and is now the whole procedure:
add a secret version, restart. No variable, no redeploy. Verify first from
inside the container with `providers probe <id>`, which works before adoption —
that ordering is deliberate and unaffected.

**The currently deployed revision still has `EVENTMILL_LLM_PROVIDERS=gcp_gemini`
baked in**, because it was deployed before this change. These defaults apply to
the next deploy; the running service needs one to pick them up.
