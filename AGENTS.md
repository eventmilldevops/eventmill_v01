# AGENTS.md

Operational context for anyone — human or agent — working in this repo.
Keep it short and current. Depth belongs in `docs/` and `cloud_install/README.md`;
this file is the "day one, don't waste an afternoon" briefing.

Event Mill is an event-record analysis platform for SOC and detection-engineering
teams. It runs as an interactive CLI shell, exposed in production as a browser
terminal (ttyd) on Cloud Run.

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

> **Unverified:** the commands above are read from `pyproject.toml` and the
> `scripts/` directory, not executed. Confirm before relying on them.
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

## Cloud deployment — read before touching `cloud_install/`

Full detail: `cloud_install/README.md`. What follows is only the material that
has actually caused failures.

### Two environment variables are mandatory. Do not let them default.

```bash
export GOOGLE_CLOUD_PROJECT="..."
export CLOUD_RUN_REGION="..."        # NO SAFE DEFAULT
export EVENTMILL_BUCKET_PREFIX="..." # NO SAFE DEFAULT
```

Persist them in `~/.eventmill/deploy.env`. Tenant-specific values are
deliberately not committed here.

Why this is the single most important line in this file:

- **Region** is embedded in the Artifact Registry image path
  (`REGION-docker.pkg.dev/PROJECT/eventmill/event-mill`). Provisioning in one
  region and deploying in another fails at `docker push` with
  `name unknown: Repository "eventmill" not found` — *after* a full paid build.
- **Bucket prefix**, if empty, makes `framework/cloud/resolver.py` fall back to
  the literal string `eventmill`. The service then starts **successfully** and
  reads buckets that do not exist. Silent, and therefore worse.

Both defaulted implicitly in v1, and every region/bucket failure during the
first tenant bring-up traced back to that.

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
