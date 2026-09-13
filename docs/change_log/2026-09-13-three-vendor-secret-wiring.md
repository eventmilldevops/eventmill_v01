# Change Log — three-vendor key wiring in the deploy path

**Date:** 2026-09-13
**Primary Files Modified:**
`cloud_install/provision-gcp-project.sh`,
`cloud_install/provision-secrets.sh`,
`cloud_install/deploy-cloudrun-secrets.sh`,
`cloud_install/deploy-cloudrun.sh`

**No application code changed.** 974 tests pass, unchanged. This is Stage 6 of
`docs/specs/multi_provider_llm_clients.md` brought forward ahead of Stages 2–5,
deliberately: the point is to prove the secret → IAM → mount → container chain
works for Anthropic and OpenAI keys **before** any code is written against them.

---

## Why infrastructure first

The reverse order is how this project has already been bitten. The 3.8 Flash swap
was correct in source and inert in the environment for a whole session because a
`.env` pin outranked the manifest silently. Wiring the keys first means that when
Stage 5 makes `_discover_models` provider-aware, the only untested variable is
the code — the keys are already known to arrive.

It also matches the operator's framing: infrastructure is provisioned once and
uniformly; adoption of a vendor is a later, per-module decision.

## The design: provision all four, seed two with placeholders

Every secret Event Mill can mount is created for every project, whether or not
the operator uses it. Gemini takes two (the tiers are keyed separately so bulk
Flash work cannot consume Pro quota); Anthropic and OpenAI take one each, because
neither vendor splits keys by tier. The non-Gemini pair holds the literal
`placeholder` until someone adopts it.

This is strictly less machinery than the alternative. An earlier reading of
`deploy-cloudrun-secrets.sh` concluded the secret set had to be computed from the
selected providers, because `ALL_SECRETS` drives three checks that all fail
closed — Step 3's existence preflight aborts, and Cloud Run rejects a revision
naming a secret the runtime SA cannot read. Seeding all four removes the
condition: `ALL_SECRETS` stays static, the mount string stays fixed, and the
logic never has to be duplicated between this script and `cloudbuild.yaml`, where
it would drift.

The payoff is that **the revision shape is identical for every deployment**.
Adopting a vendor later is `gcloud secrets versions add` plus a restart — no
infrastructure change, no rebuild, no different deploy path.

## What each script does now

**`provision-gcp-project.sh`** — `eventmill-anthropic-api` and
`eventmill-openai-api` added to `SECRET_NAMES`. Section 7 (create, seeded
`placeholder`) and Section 8 (grant + verify `secretAccessor` for
`eventmill-runner`) both iterate that array, so the two entries are created and
bound in one pass. Idempotent: an existing project picks up only what is missing.

**`provision-secrets.sh`** — new Section 1b. These keys use the existing
interactive `add_secret_version` helper (hidden input, skippable), **not**
`create_restricted_gemini_key`, which calls `gcloud services api-keys create` —
a Google-only mechanism that issues a key restricted to
`generativelanguage.googleapis.com` and has no equivalent for another vendor.
Anthropic and OpenAI keys are issued in those vendors' consoles and pasted in,
which is the same shape as the ttyd credentials.

**`deploy-cloudrun-secrets.sh`** — the production path:

- `SECRET_ANTHROPIC` / `SECRET_OPENAI` with `EVENTMILL_SECRET_*` overrides,
  matching the existing convention, plus `LLM_PROVIDERS`
  (`EVENTMILL_LLM_PROVIDERS`, space-separated, default `gcp_gemini`).
- Both added to `ALL_SECRETS`, so Step 3 preflights their existence and Step 5
  verifies the runtime SA can read them — before an image build is paid for.
- `SECRET_MOUNTS` is built once and passed to `--set-secrets`, rather than a
  single inline string stating six mounts on one line.
  `EVENTMILL_LLM_PROVIDERS` joins `--set-env-vars`.
- An unknown provider id **exits 1 with a named error**. A typo would otherwise
  deploy with that provider silently absent, which looks like a working
  deployment until a tool tries to use it.

**Step 4's placeholder check is the change that mattered most.** It warned and
prompted to abort on *any* `placeholder` value. Adding two permanently-dormant
secrets would have made that fire on every Gemini-only deploy, training operators
to answer "y" to a prompt that exists to stop a web terminal shipping with the
password `placeholder`. It now classifies:

- the ttyd pair — always blocking
- an LLM key whose provider is named in `EVENTMILL_LLM_PROVIDERS` — blocking
- any other LLM key — reported as `·  … (provider not in use — fine)`, with a
  one-time note on how to adopt it

**`deploy-cloudrun.sh`** — the plain-env-var quick-test path. `OPENAI_API_KEY`
joins the `ANTHROPIC_API_KEY` line that was already present (from `3d47c03`,
unused and predating this work), plus `EVENTMILL_LLM_PROVIDERS`. Keys are passed
explicitly-empty rather than omitted, because `--set-env-vars` replaces the set:
passing empty *clears* a key on redeploy, while omitting the flag would leave the
previous revision's value, which is how a rotated-out key keeps working unnoticed.

A pre-deploy report prints key **presence only** — never a value, never a prefix.

## The honest caveat, written into both scripts

Until Stage 5, `_discover_models` (`shell.py:418`) gates on `spec.api_key_env`
read from `framework/llm/providers/gcp_gemini.json`, so a mounted
`ANTHROPIC_API_KEY` binds nothing. Both scripts now say so at the point the
operator would otherwise be misled:

> Confirm what arrived with `printenv` in the terminal — model discovery
> currently reads the Gemini manifest only, so `models` will not list another
> vendor even with a real key set.

Without that, a successful test reads as a failure. What this deploy proves is
key delivery, not vendor availability.

## Verified

`bash -n` clean on all four. The new logic in `deploy-cloudrun-secrets.sh` was
exercised directly for `gcp_gemini`, `gcp_gemini anthropic`, and all three —
confirming which secrets become blocking in each case — plus the built mount
string and the unknown-provider refusal (`exit 1`). `deploy-cloudrun.sh`'s
reporting block was run with mixed keys, with Gemini absent, and with everything
unset; the all-unset path does not trip `set -e`, which is the failure mode that
motivated the `cloud_install` rewrite in the first place.

Not verified: an actual deploy. That is the operator's next step, and
`DRY_RUN=1 bash cloud_install/deploy-cloudrun-secrets.sh` runs the full preflight
— existence, values, IAM — and stops before the build.

## Not done here

- `cloudbuild.yaml:117/229/257` still duplicates the preflight loop, the mount
  string and the secret-name substitutions, and will keep deploying Gemini-only.
  It belongs with the rest of Stage 6.
- `Dockerfile.cloudrun:26` still installs neither the `openai` nor the
  `anthropic` SDK; no `llm-openai` / `llm-anthropic` extras exist in
  `pyproject.toml`. `openai` must be `>=1.66` when added — the Responses API the
  plan specifies landed there.
- `cloud_install/docker-compose.cloudrun.yml:21` still carries only the two
  Gemini vars for the local-container path.
- `cloud_install/README.md` env tables and `setup-deploy-server.sh:108` are
  documentation follow-on.
