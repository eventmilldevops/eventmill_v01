# AGENTS.md

Operational context for anyone — human or agent — working in this repo.
Keep it short and current. Depth belongs in `docs/` and `cloud_install/README.md`;
this file is the "day one, don't waste an afternoon" briefing.

Event Mill is an event-record analysis platform for SOC and detection-engineering
teams. It runs as an interactive CLI shell, exposed in production as a browser
terminal (ttyd) on Cloud Run.

---

## Where the work stands — 2026-09-14

Branch `llm_5`. **Five providers bind concurrently, a tool can be pointed at
any of them, and the projector has been run across vendors.** Plan:
`docs/specs/multi_provider_llm_clients.md` (Part 1, the framework) and
`docs/specs/projector_three_vendor_run.md` (the demonstration, now through
Stage E).

| | State |
|---|---|
| Gemini, Anthropic, OpenAI clients | done; all six tier clients verified live on Cloud Run 2026-09-13 |
| `(provider_id, tier)` routing, no cross-vendor fallback | done |
| `connect` binds every configured provider; `use <provider> [for <tool>]` | done |
| `EVENTMILL_LLM_PROVIDERS` defaults to every known provider everywhere | done |
| Daybreak Red + Blue as their own providers; `vendor` split from `provider_id` | done 2026-09-14 (`f84adfc`) |
| Daybreak **Red** probed + full projector run on Cloud Run | done 2026-09-14 — manifest PARTIAL: limits and `thinking_levels` still documented, not measured |
| Daybreak **Blue** | **registered, never called, and will not be** — manifest stays UNVERIFIED |
| Adding a provider needs no code | **proven** — Red was the first provider added after the seam settled: one manifest, one secret, worked first time out. Swapping Red for e.g. Kimi 3 should need no code either (a vendor with its own SDK surface still needs a client) |
| Daybreak Red access | **short-term** — treat it as a temporary tenant of the seam, not a fixture |
| Projector run record names provider **and** vendor, hashes the prompt (schema v5) | done |
| Group summary: recurrence per provider, agreement across them | done |
| **The live cross-vendor run (Stage E)** | done 2026-09-14 — Gemini 3.1 Pro vs Daybreak Red completed with very similar output; `openai` and `anthropic` worked; `summarize_run_group` worked. Qualitative sign-off: runs-per-vendor and the `stepstate-medium-2` score were not captured |
| Group summary counts **provider ids**, not vendors | **live overclaim**: `openai` and `openai_daybreak_red` are both `vendor: openai` and both bound by default, so a route the two of them find grades as two-provider agreement. Recommendation: grade on `model.vendor` (can only lower a grade). Recurrence stays per provider id |
| ~~Probe Blue, then the Red/Blue A/B~~ | **retired, not deferred** — no Blue access, so the experiment that was to settle the grading row above will never run. Decide it on judgment: recommendation is to grade on `model.vendor` |
| Does the agreement grade discriminate? | **open** — two independent vendors converging is also consistent with the prompt admitting few readings. Needs a flow map with ambiguous routes |

**PDF page limits — fixed 2026-09-14, and how they work now:**

- The guard reads **the provider actually routed to**
  (`_pdf_context_overflow`). Gemini takes 1000 pages / 50 MB at 560 tokens a
  page. Measured 2026-09-24: OpenAI 600 pages / 50 MB at ~605 tokens, and
  Anthropic 250 pages / 24 MB at ~2400 tokens. Anthropic's documented 32 MB
  includes the base64 encoding, and an oversized request arrives as a dropped
  connection. Each manifest's `_verified` note says which figures are measured.
- Over a provider's limit the call is **refused up front** with both ways out
  named: run it on Gemini, or split the document. That is the intended
  behaviour for a triage tool, not a gap to close.
- `threat_intel_ingester` no longer imposes a **second** page limit. It had a
  `max_pages` default of 50 that truncated silently, so a 150-page report
  ingested as 50 pages was indistinguishable from a 50-page report ingested
  whole. The default is now "read it all"; an explicit `max_pages` (1–1000) is
  honoured as a cost ceiling and reported as `pages_dropped`.

**Ingestion, validated 2026-09-14 on a 154-page report:** 154 pages read in
~345 s, 169 IOCs, 45 attack paths, artifact consumed by the visualizer. Two
things that run exposed:

- **Retired ATT&CK ids no longer demote a finding.** The bundled DB is 19.2;
  models emit pre-v19 numbering (`T1562.001`, `T1656`), which used to be
  marked non-ATT&CK. `resolve_retired_technique()` now remaps them — curated
  map for renamed ids, name matching for the rest — across both
  `mitre_mappings` and the attack graph, recording
  `technique_id_retired_from`. A split technique (`T1562` -> six successors)
  is deliberately left flagged rather than guessed at.
- **The latency model is ~6.3x pessimistic** and is **not** yet corrected:
  it estimated 2185 s for that 345 s run, 85% of it from
  `seconds_per_page=12.0`. The symptom is over-splitting (24 batches sized by
  pages, not by work), which separates pages that should be read together.
  Retune with `EVENTMILL_NATIVE_BASE_S` / `_S_PER_PAGE` / `_S_PER_CANDIDATE`
  before trusting any estimate — and **do not** add a planner budget check
  first: against this model it would refuse runs that succeed.

  Those three are read per execution, so **no rebuild is needed** — but they
  must be passed to the service. All four deploy paths now forward them
  (`cloudbuild.yaml` substitutions `_NATIVE_*`, `deploy-cloudrun-secrets.sh`,
  `deploy-cloudrun.sh`, `docker-compose.cloudrun.yml`), so set them in
  `~/.eventmill/deploy.env` and redeploy. For a one-off experiment use
  `gcloud run services update --update-env-vars=...`; note `--update-env-vars`,
  not `--set-env-vars`, which replaces the whole environment and would drop
  `GOOGLE_CLOUD_PROJECT`, the bucket prefix and the provider list.

**Most likely to bite next:**

1. **`run --file_path C:\Users\...` silently loses its backslashes.**
   `_parse_flag_payload` uses `shlex.split` in POSIX mode, so the path arrives
   as `C:Usersdleecemap.json` and the tool reports `ARTIFACT_UNREADABLE` naming
   the mangled path. Quote it, or use forward slashes. Unfixed.
2. **`validate_manifests.py` exits non-zero on 16 pre-existing errors** — 15
   `stability` values the schema does not define, plus a capability-namespace
   pattern that rejects underscores. Both are behaviour decisions, not typos;
   nothing in the build or deploy path runs the validator.

Read `docs/change_log/` newest-first for how any of it got that way; the
entries dated 2026-09-14 are this thread.

---

## Commands

Python >= 3.11 (`pyproject.toml` targets 3.11; the container uses 3.12).

```bash
pip install -e ".[all]"          # dev + gcp + all plugin extras

pytest                           # testpaths = tests/, plugins/  (test_*.py)
ruff check .                     # line-length 88, rules E,F,I,N,W,UP
black .                          # line-length 88
mypy framework plugins           # ignore_missing_imports = true

python scripts/validate_manifests.py     # plugin manifests
python scripts/validate_schemas.py       # JSON schemas
python scripts/generate_tool_catalog.py  # regenerate the tool catalog
```

Run the shell locally: `python -m framework.cli.shell` (or the `eventmill`
console script).

Verified as of 2026-09-14: `pytest` (**1095 passing**, 0 skipped, 0 xfailed) and
`validate_schemas.py` (34 valid) both run. `ruff`, `black` and `mypy` are in the
`dev` extra but are still **not installed** in the environment this was checked
from, so a clean lint remains unconfirmed — install with
`pip install -e ".[dev]"` before claiming one.

On Windows, prefix the `scripts/` validators with `PYTHONIOENCODING=utf-8`;
they print ✓/✗ and crash on cp1252 otherwise. The same trap applies to reading
any repo JSON or Markdown from Python — pass `encoding="utf-8"` explicitly, or
em dashes come back as mojibake and you will "fix" a file that was fine.

> **`validate_manifests.py` currently exits non-zero with 15 errors**, all
> `'stable' is not one of ['experimental','verified','core','deprecated']`.
> This is pre-existing and unrelated to any recent change: 15 of 16 manifests
> declare `stability: "stable"`, which is not a defined level. Per
> `tool_plugin_spec.md`, `stability` governs visibility and auto-invoke policy,
> so mapping it to `verified` or `core` is a behaviour decision, not a typo fix.
> Nothing in the build or deploy path runs the validator, so it does not block
> a release. Do not "fix" it by widening the enum without asking.
>
> Known inconsistency: `asyncio_mode = "auto"` is commented out in
> `[tool.pytest.ini_options]` with the note "Uncomment when pytest-asyncio is
> installed", but `pytest-asyncio` **is** in the `dev` extra. Async tests may be
> silently skipped.

---

## Layout

```
framework/          core: CLI shell, LLM backends, cloud resolver, plugin loader
  cli/shell.py      the interactive shell; entry point
  cloud/resolver.py bucket resolution (pillar + common), region-independent
plugins/            per-pillar analysis tools
cloud_install/      GCP provisioning + Cloud Run deployment
scripts/            manifest/schema validation, catalog generation
tests/              pytest; also collects tests under plugins/
docs/               change_log, guides, reference, specs
```

Runtime detects Cloud Run via the `K_SERVICE` env var — that switches file
resolution to GCS and logging to JSON for Cloud Logging.

---

## LLM models — read before changing anything under `framework/llm/`

**The layer is no longer vendor-wired.** As of 2026-09-13 the Google SDK lives
only in `framework/llm/clients/gemini.py`; `framework/llm/dispatcher.py` talks
to whatever it holds through the `LLMModelClient` protocol in `model_client.py`
and imports no vendor SDK — `tests/framework/test_provider_seam.py` enforces
that with an `ast` walk over its imports. Adding a provider means a new file
under `clients/` and a new manifest under `providers/`, and nothing else.

**Three providers are implemented and any combination can be bound at once**
(2026-09-14). Plan: `docs/specs/multi_provider_llm_clients.md`.

| Provider | light | heavy | Key env var(s) | Input | Output |
|---|---|---|---|---|---|
| `gcp_gemini` | `gemini-3.8-flash` | `gemini-3.1-pro-preview` | `GEMINI_FLASH_API_KEY`, `GEMINI_PRO_API_KEY` | 1,048,576 | 65,536 |
| `anthropic` | `claude-sonnet-5` | `claude-opus-5` | `ANTHROPIC_API_KEY` | 1,000,000 | 128,000 |
| `openai` | `gpt-5.6-terra` | `gpt-5.6-sol` | `OPENAI_API_KEY` | 400,000 | 128,000 |

Each provider's manifest under `framework/llm/providers/` is the single source
of truth for its model ids, token limits, accepted thinking levels and
capabilities; do not hardcode any of them elsewhere. **The three do not share
numbers** — Anthropic and OpenAI cap output at 128,000 against Gemini's 65,536,
so anything that reads one provider's limits for another is wrong.

Only Gemini splits keys by tier, so bulk Flash work cannot consume Pro quota;
the other two issue one key per account.

`EVENTMILL_LLM_PROVIDERS` (space-separated) names which providers a session may
bind; every deploy path and `.env.example` default it to **every known
provider**, because one whose key is unset or still `placeholder` is skipped at
startup anyway.

**A provider is not a vendor.** `openai`, `openai_daybreak_red` and
`openai_daybreak_blue` are three providers reaching one lab on two credentials,
so `vendor_of()` and `LLMResponse.vendor` answer the question `provider_id`
used to. Anything counting how far a finding's support extends must count
vendors; anything comparing two models counts providers. Both Daybreak colours
declare their single model under **both** tiers — see
`docs/change_log/2026-09-14-daybreak-providers.md` for why one tier would have
let `_fallback_client` answer a Red run with something else. **A mounted key is not a bound provider** — but with all three named,
a *real* key is, which is the point: adopting a vendor is a secret version and
a restart, with no variable to remember.
`providers` shows what is configured and keyed; `providers probe` proves
reachability with two cheap phases — a model listing and a few-token ping — and
works on a provider that is keyed but not yet named in that variable, so a key
can be verified before it is adopted.

`connect` cannot answer reachability: every client builds an SDK handle without
a network call, so a wrong key connects cleanly and fails at first use.

`connect` binds **every** configured provider whose key is present and is not
the placeholder — ten clients when all five are named. The first entry of
`EVENTMILL_LLM_PROVIDERS` is the session default and serves every tool that
names no provider. `connect <model_id>` is the single-provider form: it binds
that model's provider only, including its other tier for quota fallback.

**`LLMDispatcher._clients` is keyed by `(provider_id, tier)`.** Keyed by tier
alone it could not hold two vendors at once — a second provider's client under
`"heavy"` evicted the first. A tier-keyed dict is still accepted and normalised
from each client's own `provider_id`, so older call sites keep working.

**Automatic cross-provider fallback is forbidden and enforced.**
`_fallback_client` answers "the other connected tier *of the same provider*". A
quota failure must never move a session to a vendor nobody selected — the data
would go somewhere unchosen and the output would be unattributable. Deliberate
selection is the requirement; silent failover is the hazard. Provider choice
rides `TierScopedLLMClient(default_provider=...)`, never `QueryHints`, so a
plugin cannot override an operator's selection.

**`use <provider> [for <tool_name>]`** is how an operator makes that choice —
session default or per-module override, `use default` to clear, bare `use` to
report. It is session-scoped and never persisted. Selecting a provider that is
not bound, or naming a tool that does not exist, is refused rather than stored.
`ask:` follows the session default; a per-tool override does not apply to it.

**The tiers are capacity-identical.** Tier selects reasoning depth and cost, and
nothing else. Any logic that picks a tier based on how much data there is, is
wrong by construction — that was the original `max_tokens > 3500` heuristic,
now removed.

Tier precedence: **per-call `QueryHints` > manifest `model_tier` > light.** The
manifest default is applied by `TierScopedLLMClient`, one wrapper per plugin
execution, so plugins need no code for the common case. Hints that set no `tier`
(for example `thinking_level` alone) keep the manifest default rather than
overriding it.

Both tiers connect by default. A single legacy `GEMINI_API_KEY` binds to both,
and even a one-model `connect <model_id>` is wrapped in `LLMDispatcher` — a bare
client would skip token clamping, the PDF context guard, the retired-model retry,
and native document handling.

Non-obvious things that have already caused bugs here:

- **PDF page cost is not a constant.** Under Gemini 3.x it is set by
  `media_resolution`: `low` 280, `medium` 560 (default), `high` 1120 tokens per
  page, plus native text which is free. A 1000-page PDF is 1.12M tokens at
  `high` and does not fit the 1M window; `query_with_document()` refuses that up
  front rather than failing mid-call.
- **Default thinking effort moved to `medium` in 3.x.** Bulk extraction should
  pass `thinking_level="low"` or it pays reasoning cost per chunk for
  pattern-matching work. **One deliberate exception**:
  `threat_intel_ingester`'s native PDF calls run at `medium` (2026-09-12) on the
  judgement that reading a report is not pure pattern work. That costs usable
  output per call — `_native_content_budget()` reserves 16,384 instead of 4,096,
  so 49,152 rather than 61,440 — and therefore batches dense documents more
  finely. Measured on a 94-IOC synthetic report it bought no extra IOCs and
  ~40% latency; the case for it is real prose, not dense indicator lists.
- **Thinking tokens are spent from `max_output_tokens`.** The cap is not a
  content budget: reasoning is drawn from it first and the answer is cut off
  with `finish_reason="MAX_TOKENS"`, `ok=True` and no error — a caller that
  checks only `ok` treats half a reply as a whole one. Size a long reply
  against `max_output_tokens - thinking_reserve_tokens(level)` (declared in
  `output_budget` in the provider manifest), and check `LLMResponse.truncated`.
  A 16,384-token document call once returned 70 of ~150 expected IOC records
  because ~11k of that cap went to thinking.
- **`temperature`, `top_p`, `top_k` are deprecated in 3.x.** The code sets none
  of them. Do not add them back.
- **The heavy tier is a Preview endpoint** and can be retired with ~2 weeks'
  notice. On `NOT_FOUND` the dispatcher retries against the tier's
  `fallback_model_id`. `EVENTMILL_MODEL_HEAVY` repoints it without a code change.
- **The light tier is GA and declares no fallback.** Verified live 2026-09-12:
  `models/gemini-3.8-flash` exists, 1,048,576 in / 65,536 out, `thinking_level`
  honoured, native PDF read. `EVENTMILL_MODEL_LIGHT` and
  `EVENTMILL_MAX_OUTPUT_LIGHT` repoint the model and its cap without a code
  change — set them together, since the cap otherwise still comes from the
  manifest. An override naming the manifest's own model is treated as a
  redundant pin, not a substitution, and does not warn.
- **An `EVENTMILL_MODEL_*` pin silently outranks the manifest.** A deployment
  `.env` pinning a tier is what a manifest tier change has to get past; check
  there first when a model change appears to have done nothing.
- **PDF page cost measured on 3.8 Flash (2026-09-12)**, marginal tokens per
  letter-size page: `low` 266, `medium` 520, `high` 1102, against the declared
  280 / 560 / 1120. The declared values are kept as a deliberate upper bound —
  they are 2-7% conservative and page size is not held constant across
  documents, and the guard's job is to refuse before the provider does.
- **`model_used` is what was asked for; `model_version` is what ran.** The
  dispatcher records both — the second from the provider's response — so a
  version change inside one alias is visible when comparing two models over
  the same corpus. The projector writes them as `model_configured` and
  `model_served` (run record `schema_version` 3).
- **Use `models.generate_content()`, not the Interactions API.** The Interactions
  gateway caps input at 32,768 tokens regardless of the model's real context
  window — a documented trap that looks like a model limitation.
- `google-genai >= 1.69.0` is required for `media_resolution` and
  `thinking_level`. The container resolves 2.x, whose breaking changes are
  confined to the Interactions API.

---

## Cloud deployment — read before touching `cloud_install/`

Full detail: `cloud_install/README.md`. What follows is only the material that
has actually caused failures.

### Two environment variables are mandatory. Do not let them default.

```bash
export GOOGLE_CLOUD_PROJECT="..."
export CLOUD_RUN_REGION="..."        # NO SAFE DEFAULT
export EVENTMILL_BUCKET_PREFIX="..." # NO SAFE DEFAULT
```

Persist them in `~/.eventmill/deploy.env`. `provision-gcp-project.sh` and
`deploy-cloudrun-secrets.sh` load that file automatically, with anything already
exported in your shell taking precedence. `gcloud builds submit` cannot read it,
so the Cloud Build path still needs an explicit `source` plus `--substitutions`.
Tenant-specific values are deliberately not committed here.

Why this is the single most important line in this file:

- **Region** is embedded in the Artifact Registry image path
  (`REGION-docker.pkg.dev/PROJECT/eventmill/event-mill`). Provisioning in one
  region and deploying in another fails at `docker push` with
  `name unknown: Repository "eventmill" not found` — *after* a full paid build.
- **Bucket prefix**, if empty, makes `framework/cloud/resolver.py` fall back to
  the literal string `eventmill`. The service then starts **successfully** and
  reads buckets that do not exist. Silent, and therefore worse.

Both defaulted implicitly in v1, and every region/bucket failure during the
first tenant bring-up traced back to that. Every script now refuses to run
without an explicit region, and the `deploy.env` template ships
`CLOUD_RUN_REGION` blank on purpose — a pre-filled region silently satisfies
the check and reintroduces the bug.

### IAM model

Production runs as `eventmill-runner`, using workload identity — no key files.
The `eventmill-gcs-sa` secret exists for legacy reasons and is normally unused.

**IAM is written in exactly one place: `provision-gcp-project*.sh`, at bootstrap.
Deploy scripts only verify.** This keeps the deploy path free of any
`*.setIamPolicy` permission, so it runs unchanged under a CI service account
that must not be able to rewrite IAM. Preserve this split.

**Four `actAs` delegations** are required. A service account is both an identity
and a resource; `roles/iam.serviceAccountUser` on the *target SA* grants
`iam.serviceAccounts.actAs`, which permits attaching that identity to a
workload. It does **not** grant that SA's own permissions.

| Actor | Target SA | Needed for |
|---|---|---|
| operator | default compute SA | `gcloud builds submit` (build runs as it) |
| operator | `eventmill-runner` | `gcloud run deploy --service-account=...` |
| `eventmill-runner` | default compute SA | app submitting Zeek Cloud Build jobs |
| Cloud Build SA | `eventmill-runner` | CI deploying Cloud Run |

v1 configured only the two machine-to-machine rows and silently omitted the two
operator rows, so a hand-run deploy failed twice with
`Permission 'iam.serviceAccounts.actAs' denied`, once per target SA.

**Operator roles**, all verified by the deploy preflight before anything is built:

| Scope | Role |
|---|---|
| project | `roles/storage.admin` |
| project | `roles/artifactregistry.admin` |
| project | `roles/cloudbuild.builds.editor` |
| project | `roles/serviceusage.serviceUsageConsumer` |
| project | `roles/run.admin` |
| project | `roles/logging.viewer` |
| project | `roles/secretmanager.admin` |
| on `eventmill-runner` | `roles/iam.serviceAccountUser` |
| on default compute SA | `roles/iam.serviceAccountUser` |

Non-obvious traps, each of which cost real time:

- `roles/artifactregistry.repoAdmin` does **not** include
  `repositories.create`. Only `admin` and `createOnPushRepoAdmin` do. Console
  name for the right one is "Artifact Registry Administrator" — *without*
  "Repository".
- `roles/cloudbuild.builds.editor` alone is insufficient: `gcloud builds`
  additionally needs `serviceusage.services.use`
  (`roles/serviceusage.serviceUsageConsumer`). Holders of `editor`/`owner` never
  see this, so it is easy to miss.
- Streaming build logs from the **default** logs bucket requires project
  `roles/viewer`. Setting `options: logging: CLOUD_LOGGING_ONLY` in the build
  config reduces that to `roles/logging.viewer`. All build configs here set it;
  keep it that way.
- `roles/editor` cannot set IAM policy. If provisioning prints
  `⚠ Could not grant roles/...`, that is usually why.

### Debugging discipline

**Never infer a cause from a generic GCP error.** The single largest time sink
in the first bring-up was error handling of the form
`cmd > /dev/null 2>&1` followed by a hardcoded guess — which reported the same
geo-block as "bucket name already taken globally" and as "Secret not found".

Measure instead, with `testIamPermissions`. It returns the subset of requested
permissions the caller holds; anything absent is missing.

```bash
# Project-scoped
curl -s -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  -d '{"permissions":["cloudbuild.builds.create","serviceusage.services.use"]}' \
  "https://cloudresourcemanager.googleapis.com/v1/projects/PROJECT:testIamPermissions"

# Service-account-scoped — a DIFFERENT resource
curl -s -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  -d '{"permissions":["iam.serviceAccounts.actAs"]}' \
  "https://iam.googleapis.com/v1/projects/-/serviceAccounts/SA_EMAIL:testIamPermissions"
```

Both are needed. `actAs` lives on the service account, so a project-level probe
returns a misleading all-clear while the deploy still fails. There is no
`gcloud projects test-iam-permissions` command; use the REST API.

### Environment gotcha: Google geo-blocks some hosting IPs

Symptom, on any `*.googleapis.com` call:

```
403 We're sorry, but this service is not available in your location
```

This is **not** IAM and **not** a missing resource. Google's geolocation
database misclassifies certain ranges — OVH IPv6 is a documented, currently
active case. The console works because the API call originates from Google's
frontend, not your host.

```bash
# Confirm: 401 = reachable, 403 = geo-blocked
curl -4 -sS -o /dev/null -w 'v4: %{http_code}\n' https://storage.googleapis.com/storage/v1/b?project=PROJECT
curl -6 -sS -o /dev/null -w 'v6: %{http_code}\n' https://storage.googleapis.com/storage/v1/b?project=PROJECT

# Fix if IPv6-only: prefer IPv4
echo 'precedence ::ffff:0:0/96  100' | sudo tee -a /etc/gai.conf
```

`/etc/gai.conf` affects glibc `getaddrinfo` only. Go binaries (including
`docker`) use their own resolver and ignore it; `GODEBUG=netdns=cgo` is a
best-effort workaround. Google's "report IP problems" form does not accept IPv6
ranges. Cloud Shell always works and is the reliable fallback.

### Other operational notes

- Build context **must** be the repo root — `Dockerfile.cloudrun` copies
  `pyproject.toml`, `README.md`, `framework/`, `plugins/`. Scripts derive the
  root from `BASH_SOURCE`; do not regress to passing `.`.
- Provisioning seeds every secret with the literal string `placeholder`. Run
  `provision-secrets.sh` or the LLM is dead and the web terminal password is
  `placeholder`.
- **Seven secrets are provisioned, and all six LLM/ttyd ones are mounted, but
  two are dormant by design.** `eventmill-anthropic-api` and
  `eventmill-openai-api` are created and IAM-bound like the rest and hold
  `placeholder` until someone adopts that vendor. This keeps the revision shape
  identical for every deployment, so adopting a provider is a new secret version
  plus a restart rather than an infrastructure change.
  `EVENTMILL_LLM_PROVIDERS` (space-separated) names the ones a session may bind
  and defaults to **all three** on every deploy path; an unknown id is refused
  rather than ignored. **A placeholder in an unadopted provider is the expected
  steady state** — Step 4 reports it as `·` and does not prompt. Because every
  provider is named by default, "configured" no longer means "adopted", so
  Step 4 blocks on **values**: ttyd holding `placeholder`, or no LLM provider
  holding a real key at all. Do not make a per-provider placeholder blocking
  again; it would fire on every deployment that has one vendor's key and not
  the other two, and train operators to dismiss the check that stops ttyd
  shipping with the password `placeholder`.
- **A real key now does bind its provider.** `_discover_models` walks every
  configured provider's manifest and `connect` builds each tier through the
  provider registry, so `ANTHROPIC_API_KEY` holding a real value appears in
  `models` and is selectable with `use`. A key that is unset or still
  `placeholder` is skipped and named. `providers` is the diagnostic;
  `printenv` is no longer the only way to see a key arrived.
- Deploys default to `--allow-unauthenticated`; the only gate is shared ttyd
  basic auth. `ALLOW_UNAUTH=false` switches to IAM (`roles/run.invoker`).
  Prefer that for anything holding real investigation data.
- There is no `.gcloudignore`; `gcloud` falls back to `.gitignore`, which does
  **not** exclude `test_outputs/`. It uploads to the Cloud Build staging bucket
  on every deploy.
- Artifact Registry repos are **regional**. Check for same-named repos in other
  regions before assuming one is missing: `gcloud artifacts repositories list`.

---

## Completed refactor: `*-v2` folded into the originals

Done. `provision-gcp-project.sh`, `deploy-cloudrun-secrets.sh` and
`cloudbuild.yaml` are now the v2 implementations, verified end-to-end against a
live tenant. The superseded v1 files are kept alongside as `*.bak` for
reference; they are not on any documented path and should not be run.

Defects that must **not** be reintroduced:

1. **Silent aborts.** v1 runs under `set -e` with checks written as
   `cmd > /dev/null 2>&1`. One unguarded failure —
   `echo -n "" | gsutil cp - "$dest"` in the bucket-folder loop — killed the run
   with zero output, skipping Artifact Registry creation, secret creation, and
   all secret IAM bindings. v2 does not use `set -e`; it accumulates failures
   and always reaches a summary with a non-zero exit.
2. **Guessed error causes.** Report the actual stderr. Never hardcode a reason.
3. **Implicit region/prefix defaults.** v2 refuses to run without them.
4. **IAM writes in the deploy path.** Keep IAM writes in provisioning only.
5. **Unverified IAM bindings.** v1 printed `✓ can read <secret>` unconditionally
   because the call ended in `> /dev/null 2>&1` with no status check. Verify.
6. **CWD-dependent build context.** Derive the repo root from `BASH_SOURCE`.
7. **`gsutil`.** Use `gcloud storage`. v1 mixed both.
8. **Wrong SA in grants.** v1's deploy granted secret access to the default
   compute SA while deploying as `eventmill-runner`.
9. **Missing `compute.googleapis.com`.** The default compute SA — the identity
   Cloud Build runs as — only exists once that API is enabled.
10. **"Previous revision" on a failed first deploy.** There isn't one; say so.

Region handling is now consistent everywhere: `provision-gcp-project.sh`,
`deploy-cloudrun-secrets.sh`, `deploy-cloudrun.sh` and `cloudbuild.yaml` all
refuse to run without an explicit region rather than defaulting to
`northamerica-northeast2`. The `deploy.env` template ships it blank for the
same reason — a pre-filled region silently satisfies the check.

`provision-gcp-project.sh` and `deploy-cloudrun-secrets.sh` now load
`~/.eventmill/deploy.env` automatically, with already-exported values winning.
Previously every doc told you to create that file and `source` it by hand, and
forgetting the source was the most common way to deploy against the wrong
region. `gcloud builds submit` still needs an explicit source plus
`--substitutions`, since Cloud Build cannot read your shell.

Still outstanding:

- `provision-wikijs.sh` and `deploy-wikijs.sh` still default the region. They
  are a separate optional component, untouched by the refactor.
- Script headers claim `v0.1.0`; `pyproject.toml` says `0.2.0`.

---

## Conventions

- Do not add or remove comments unless asked.
- Match surrounding style; check imports before assuming a library is available.
- Shell scripts: `bash -n` before committing. Prefer explicit error handling
  over `set -e` in anything long-running or bootstrap-related.
- Never commit tenant identifiers, secrets, or credentials. Deploy configuration
  belongs in `~/.eventmill/deploy.env`, not in the repo.
