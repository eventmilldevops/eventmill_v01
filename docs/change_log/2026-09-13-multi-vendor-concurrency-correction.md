# Change Log — multi-vendor concurrency, a corrected premise

**Date:** 2026-09-13
**Primary Files Modified:** `docs/specs/multi_provider_llm_clients.md`

**No code changed.** This records a decision that reshapes Stages 2, 5 and 6 of
the multi-provider plan, taken before any of them was built.

---

## What was wrong

The plan listed three things under *Out of scope, deliberately*:

- cross-provider fallback
- mixing providers across tiers
- per-module provider selection at runtime

The first is a genuine data-handling boundary. The other two were **requirements
from the start**, and the plan ruled them out by treating all three as the same
concern. The operator's correction:

> There was never a reason to keep Event Mill tied to a single vendor. The
> decision was one heavy and one light model per tool module, but those could be
> overridden at runtime in order to compare outputs.

The error was collapsing two different things:

| | Who chooses | Recorded on the output | Verdict |
|---|---|---|---|
| Automatic fallback on quota | nobody | no | **hazard** — stays out of scope |
| Deliberate provider selection | the operator | yes, via `provider_id` | **the requirement** |

An automatic failover sends investigation data to a vendor nobody selected and
leaves the result unattributable. A deliberate A/B run sends it to a vendor the
operator explicitly chose and stamps the result with which one. Ruling out the
second because of the first cost the plan its actual purpose.

The narrowed boundary is also much smaller than it looked: it constrains
`_fallback_client` and nothing else, rather than the shape of the design.

## What the plan now says

**Two new decisions.**

- **8 — the dispatcher's client map is keyed by tier and must be keyed by both.**
  `LLMDispatcher._clients` is `dict[str, LLMModelClient]` keyed `"light"` /
  `"heavy"`. With one vendor that is complete; with two bound at once it cannot
  express the state. It becomes `(provider_id, tier)`, with `_route()` resolving
  provider then tier, and `_fallback_client` constrained to the same provider.
- **9 — runtime override rides the scoping wrapper, not `QueryHints`.**
  `shell.py:2782` already wraps each plugin execution in `TierScopedLLMClient`
  with the manifest's `model_tier`; the provider joins it there. A `provider`
  field on `QueryHints` would put vendor choice in plugin code and let a plugin
  override an operator's A/B selection — so it is now explicitly out of scope.

**Stage 2** absorbs the `(provider_id, tier)` rekey and `EVENTMILL_LLM_PROVIDERS`
(plural, default `gcp_gemini`). Large enough to split; the rekey is the half that
must land first.

**Stage 5** gains `providers` and `use <provider> [for <tool>]` as the runtime
A/B control, and notes that `_discover_models` gating on the Gemini manifest
(`shell.py:418`) is why a mounted `ANTHROPIC_API_KEY` binds nothing until this
lands — correct in source, inert in the environment, the 09-12 failure mode.

**Stage 6** is rewritten around the operator's infrastructure call, below.

**Part 2's run design** changes materially. Concurrent binding turns "n runs per
provider" from three sequentially-configured sessions into one invocation over
one flow map — which removes the largest confound in the original design, since
three sessions differ in session state and artifact set as well as vendor. It
also raises the stakes on `provider_id` in the run record: two records from one
session may now come from two vendors, so a record without it is not a weaker
measurement but an unreadable one.

## Stage 6 — provision all three, seed two with placeholders

The operator's call, and it removes work rather than adding it:

> It would also be possible to require secrets for all three vendors in the cloud
> build process but OpenAI and Anthropic could have placeholder keys. This
> ensures a consistent build, aligns with GCP-first project principles, but makes
> extension into other LLMs something that could be done one module or tool at a
> time. Separates infrastructure from development.

Provisioning creates a fixed set of secrets regardless of which vendors are used;
OpenAI and Anthropic hold the literal `placeholder` that `provision-gcp-project.sh`
already seeds until someone adopts them.

This is strictly simpler than the alternative. An earlier reading of
`deploy-cloudrun-secrets.sh` concluded the secret set had to be computed from the
selected providers, because `ALL_SECRETS` drives three checks that all fail
closed — the Step 3 existence preflight aborts, and Cloud Run rejects a revision
naming an unresolvable secret. Seeding all three removes the condition entirely:
`ALL_SECRETS` stays static, `--set-secrets` stays fixed, and the logic does not
have to be duplicated between the shell script and `cloudbuild.yaml`, where it
would drift.

It also makes adoption a one-module decision — `gcloud secrets versions add` plus
a `use` override, with no redeploy and no infrastructure change — which is what
makes Part 2's module-at-a-time sequence practical rather than theoretical.

One detail this creates, recorded in the stage: **Step 4's placeholder check
(`deploy-cloudrun-secrets.sh:550`) currently warns and prompts to abort on any
`placeholder` value.** Once the new secrets exist it would fire on every
Gemini-only deploy. A placeholder in an *unadopted* provider is the expected
steady state and must be informational; a placeholder in a provider named by
`EVENTMILL_LLM_PROVIDERS` stays blocking.

## Stages 0 and 1 are unaffected

Worth stating, because a premise correction this late usually costs something.
`provider_id` on both `LLMModelClient` and `LLMResponse` — landed in Stage 1 as
part of the `error_kind` work — is exactly the attribution multi-vendor A/B
needs: every response already names the vendor that produced it. And
`TierScopedLLMClient` was already the single place a manifest default becomes a
per-execution decision. Nothing from Stage 1 needs redoing.

## Sequencing, unchanged in principle

The `pyproject` extras and the Dockerfile can land any time; they only make SDKs
present. The `cloud_install` script changes should land **with or after Stage 5**,
because until `_discover_models` is provider-driven a mounted key binds nothing
and the deploy would look correct while doing nothing.
