# Event Mill v0.2.0 — Cloud Installation Guide

Deployment scripts for running Event Mill on Google Cloud Run with a
[ttyd](https://github.com/tsl0922/ttyd) web terminal frontend.

## Architecture

```
Browser (HTTPS:443) → Cloud Run → ttyd (:8080) → eventmill CLI shell
```

Cloud Run provides automatic HTTPS, scaling (0→N), and IAM-based access control.
The ttyd web terminal gives analysts a browser-based Metasploit-style shell.

## Deployment Workflow

Deployments are run from a **dedicated Linux server** with the Google Cloud
SDK and libraries pre-installed. The workflow is:

```
1. SSH into Linux deploy server
2. Pull latest code from GitHub
3. Authenticate to GCP (if session expired)
4. Run deploy script (deploy config is loaded automatically)
```

```bash
ssh deploy-server
cd ~/eventmill_v01
git pull
bash cloud_install/deploy-cloudrun-secrets.sh
```

`~/.eventmill/deploy.env` is loaded automatically — anything already exported
in your shell wins over it. Only `gcloud builds submit` still needs an explicit
`source`, because Cloud Build cannot read your shell.

## First-Time Setup (Deploy Server)

Run the bootstrap script once on the Linux deploy server:

```bash
# Download and run directly, or clone first
curl -sL https://raw.githubusercontent.com/eventmilldevops/eventmill_v01/main/cloud_install/setup-deploy-server.sh | bash
```

Or manually:

```bash
git clone https://github.com/eventmilldevops/eventmill_v01.git ~/eventmill_v01
bash ~/eventmill_v01/cloud_install/setup-deploy-server.sh
```

This will:
- Verify `gcloud` and `docker` are available
- Clone or pull the repo to `~/eventmill_v01`
- Create `~/.eventmill/deploy.env` config template
- Make deploy scripts executable

Then configure:

```bash
nano ~/.eventmill/deploy.env     # GOOGLE_CLOUD_PROJECT and CLOUD_RUN_REGION are required and blank
gcloud auth login                # Authenticate to GCP
gcloud config set project YOUR_PROJECT_ID
```

`provision-gcp-project.sh` and `deploy-cloudrun-secrets.sh` **load
`~/.eventmill/deploy.env` automatically** — anything already exported in your
shell takes precedence. The explicit `source` in the examples below is harmless
and still required for `gcloud builds submit`, which cannot read the file.

> **Important:** `EVENTMILL_BUCKET_PREFIX` must match the prefix used when running
> `provision-gcp-project.sh`. Storage resolution will silently use the wrong buckets
> if this value is missing or mismatched.
>
> `CLOUD_RUN_REGION` must match too, and is left blank in the template on
> purpose. Every script now refuses to guess it: the Artifact Registry image
> path embeds the region, so provisioning in one and deploying in another fails
> at `docker push` — after a full paid build.

## Deploy Commands

### Production deploy (Secret Manager — recommended)

```bash
source ~/.eventmill/deploy.env
cd ~/eventmill_v01
git pull
bash cloud_install/deploy-cloudrun-secrets.sh
```

### Quick deploy (env var secrets — dev/testing only)

```bash
source ~/.eventmill/deploy.env
export GEMINI_FLASH_API_KEY="your-flash-key"
export GEMINI_PRO_API_KEY="your-pro-key"
export TTYD_USERNAME="admin"
export TTYD_PASSWORD="changeme"
cd ~/eventmill_v01
bash cloud_install/deploy-cloudrun.sh
```

### CI/CD via Cloud Build

Connect GitHub repo to Cloud Build, then trigger manually:

```bash
cd ~/eventmill_v01
source ~/.eventmill/deploy.env
gcloud builds submit \
    --project="${GOOGLE_CLOUD_PROJECT}" \
    --config=cloud_install/cloudbuild.yaml \
    --substitutions="_REGION=${CLOUD_RUN_REGION},_BUCKET_PREFIX=${EVENTMILL_BUCKET_PREFIX}" \
    .
```

Substitutions:

| Substitution | Default | Description |
|---|---|---|
| `_REGION` | **none — required** | Cloud Run region. Must match the region you provisioned in; the build fails fast if unset rather than guessing. |
| `_BUCKET_PREFIX` | `${PROJECT_ID}-eventmill` | GCS bucket prefix — must match provisioned buckets |

Cloud Build cannot read `~/.eventmill/deploy.env`, so `_REGION` has to be passed
explicitly here even though the shell scripts pick it up automatically. When
wiring a **trigger**, set both in the trigger's substitution config.

## Files

| File | Purpose |
|------|---------|
| `provision-gcp-project.sh` | **Run first** — enables APIs, creates SA, bucket, secrets |
| `provision-secrets.sh` | Interactive — sets real values for Secret Manager entries |
| `setup-deploy-server.sh` | One-time bootstrap for the Linux deploy server |
| `Dockerfile.cloudrun` | Multi-stage container image with ttyd + eventmill |
| `deploy-cloudrun.sh` | Basic Cloud Run deploy (env var secrets) |
| `deploy-cloudrun-secrets.sh` | Production deploy with GCP Secret Manager |
| `cloudbuild.yaml` | Cloud Build CI/CD pipeline |
| `docker-compose.cloudrun.yml` | Local testing of the Cloud Run image |
| `*.bak` | Superseded v1 scripts, kept for reference only — do not run |

## GCP Project Provisioning (first time only)

```bash
export GOOGLE_CLOUD_PROJECT="your-project-id"
export CLOUD_RUN_REGION="us-central1"          # required — no default
export EVENTMILL_BUCKET_PREFIX="your-prefix"   # optional; derived if unset

# 1. Provision APIs, service account, buckets, Artifact Registry, secret entries
bash cloud_install/provision-gcp-project.sh

# 2. Set real secret values (interactive prompts, nothing in shell history)
bash cloud_install/provision-secrets.sh
```

This creates everything the project needs: APIs enabled (including
`apikeys.googleapis.com` for key creation and `logging.googleapis.com` for
audit logging), a dedicated service account with least-privilege IAM roles,
GCS buckets (per-pillar + common) with lifecycle rules, Artifact Registry,
and Secret Manager entries for dual Gemini API keys.

Provisioning is the **only** place IAM is written. The deploy scripts merely
verify, so the deploy path needs no `*.setIamPolicy` permission and can run
under a CI service account that must not be able to rewrite IAM.

When it finishes it prints the exact `~/.eventmill/deploy.env` to save, with
the resolved project, region and bucket prefix filled in. The provisioning and
deploy scripts both read that file automatically on subsequent runs.

## LLM Models

The deployed service binds two model tiers, configured declaratively in
`framework/llm/providers/gcp_gemini.json`:

| Tier | Model | Used for |
|------|-------|----------|
| light | `gemini-3.5-flash` | Bulk work — log pattern summarization, per-chunk IOC extraction, report chunking |
| heavy | `gemini-3.1-pro-preview` | Deep reasoning — threat modeling, risk assessment, cross-document synthesis, `ask:` |

Both accept 1,048,576 input and 65,536 output tokens, so the tier is a choice
about reasoning depth and cost, never about how much fits. Each plugin declares
its default tier as `model_tier` in its manifest; a plugin can override per call.

Keys are separate per tier so high-volume light-tier traffic cannot exhaust the
heavy tier's quota. If one tier is exhausted, the dispatcher falls back to the
other and says so in the log.

> The heavy tier is pinned to a **Preview** endpoint, which Google may retire
> with roughly two weeks' notice. If it starts returning `NOT_FOUND`, the
> dispatcher automatically retries against the tier's declared fallback and logs
> the substitution. To pin a different model without a code change, set
> `EVENTMILL_MODEL_HEAVY`.

## Storage Architecture

Event Mill uses **per-pillar GCS buckets** for data isolation plus a shared
**common bucket** for cross-pillar reference data (e.g. vetted threat intel).

### Naming Convention

```
{EVENTMILL_BUCKET_PREFIX}-log-analysis         ← log analysis artifacts
{EVENTMILL_BUCKET_PREFIX}-network-forensics    ← network forensics artifacts
{EVENTMILL_BUCKET_PREFIX}-threat-modeling       ← threat modeling artifacts
{EVENTMILL_BUCKET_PREFIX}-common               ← shared reference data
```

Default prefix: `{your-project-id}-eventmill` (auto-derived from `GOOGLE_CLOUD_PROJECT`). Set `EVENTMILL_BUCKET_PREFIX` to override.

### Workspace Folders

Buckets can contain **workspace folders** to separate incidents:

```
gs://eventmill-log-analysis/
├── incident-2024-03/
│   ├── auth.log
│   └── syslog.log
├── incident-2024-04/
│   └── firewall.log
└── standalone-file.log        ← bucket root (no workspace)
```

In the CLI, use `workspace incident-2024-03` to scope file resolution.
The `load` command checks both the pillar bucket and the common bucket.

### File Resolution Order

When a user runs `load auth.log`:

1. Local file path (if exists on disk)
2. Pillar bucket + workspace folder
3. Pillar bucket root
4. Common bucket + workspace folder
5. Common bucket root

If both pillar and common have the file, **pillar wins** (investigation-specific
data takes precedence over shared reference data).

### Automated Ingestion

External automations write directly to the appropriate pillar bucket.
Which automations write to which buckets is **site-specific** and managed
by the implementation team outside of Event Mill. The common bucket is
for curated reference data shared across all investigations.

### Per-Pillar Overrides

Override any pillar bucket name via environment variable:

```bash
export EVENTMILL_BUCKET_LOG_ANALYSIS="my-custom-log-bucket"
export EVENTMILL_BUCKET_COMMON="my-shared-data"
```

### Cloud Build Permissions (default compute SA)

Cloud Build uses the project's **default compute service account** to upload
source tarballs to GCS. If you see a `storage.objects.get` permission error
during `gcloud builds submit`, the default compute SA needs storage access.

The `provision-gcp-project.sh` script handles this automatically. To fix
manually or verify:

```bash
# 1. Find your project number
PROJECT_NUMBER=$(gcloud projects describe ${GOOGLE_CLOUD_PROJECT} --format="value(projectNumber)")

# 2. The default compute SA follows this pattern:
#    {PROJECT_NUMBER}-compute@developer.gserviceaccount.com
echo "Default compute SA: ${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"

# 3. Grant storage access (source tarball upload)
gcloud projects add-iam-policy-binding ${GOOGLE_CLOUD_PROJECT} \
    --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
    --role="roles/storage.objectAdmin" \
    --quiet

# 4. Grant Artifact Registry access (Docker image push)
gcloud projects add-iam-policy-binding ${GOOGLE_CLOUD_PROJECT} \
    --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
    --role="roles/artifactregistry.writer" \
    --quiet
```

## Secret Manager Setup

`provision-secrets.sh` handles this automatically — it creates restricted
Gemini API keys via `gcloud services api-keys create` and stores them in
Secret Manager. To manage secrets manually:

```bash
# Dual Gemini API keys (restricted to generativelanguage.googleapis.com)
# Display names match the OS env vars for traceability:
#   GEMINI_FLASH_API_KEY  →  eventmill-gemini-flash-api
#   GEMINI_PRO_API_KEY    →  eventmill-gemini-pro-api

# ttyd basic auth credentials
echo -n "analyst" | gcloud secrets versions add eventmill-ttyd-user --data-file=-
echo -n "strong-password" | gcloud secrets versions add eventmill-ttyd-cred --data-file=-
```

### GCS Access (Workload Identity)

Cloud Run uses **workload identity** for GCS access — no service account key
file is needed. The deploy script assigns the `eventmill-runner` service
account to the Cloud Run service via `--service-account`, and GCP's metadata
server provides credentials automatically.

This approach:
- Complies with org policies that disable SA key creation (`constraints/iam.disableServiceAccountKeyCreation`)
- Eliminates the risk of leaked key files
- Requires no secret rotation for GCS access

The `eventmill-runner` service account is granted `roles/storage.objectUser`
at the project level by `provision-gcp-project.sh`, which allows read/write
access to all Event Mill GCS buckets (per-pillar and common).

### Audit Logging (Cloud Logging)

User activity is logged to **Cloud Logging** via the `google-cloud-logging`
library, not to the GCS artifact bucket. This provides:

- **Immutability** — Users cannot delete or modify audit logs
- **Separation** — Audit trail is separate from user-accessible artifact storage
- **Retention** — Configurable retention policies independent of user actions
- **Access control** — Separate IAM for log viewing vs. artifact access

Activity logs appear in Cloud Logging under:
```
projects/PROJECT_ID/logs/eventmill-activity
```

To view activity logs:
```bash
gcloud logging read "logName=projects/${GOOGLE_CLOUD_PROJECT}/logs/eventmill-activity" \
    --project=${GOOGLE_CLOUD_PROJECT} \
    --limit=50 \
    --format=json
```

The `eventmill-runner` service account is granted `roles/logging.logWriter`
by `provision-gcp-project.sh`, which allows writing logs but not reading or
deleting them.

## Local Image Testing (on deploy server)

Before running, set at minimum:

```bash
export GOOGLE_CLOUD_PROJECT="your-project-id"
export EVENTMILL_BUCKET_PREFIX="${GOOGLE_CLOUD_PROJECT}-eventmill"   # default — matches provision-gcp-project.sh
export GEMINI_FLASH_API_KEY="your-flash-key"
export GEMINI_PRO_API_KEY="your-pro-key"
export TTYD_USERNAME="admin"
export TTYD_PASSWORD="changeme"
```

For GCS access, choose one credential approach and uncomment the matching
volume in `docker-compose.cloudrun.yml`:

```bash
# Option A — Application Default Credentials (recommended)
gcloud auth application-default login
# Then uncomment in docker-compose.cloudrun.yml:
# - ${HOME}/.config/gcloud:/home/eventmill/.config/gcloud:ro

# Option B — Service account key file
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/sa-key.json"
# Then uncomment in docker-compose.cloudrun.yml:
# - ${GOOGLE_APPLICATION_CREDENTIALS:-/dev/null}:/app/credentials/sa-key.json:ro
```

```bash
docker compose -f cloud_install/docker-compose.cloudrun.yml up --build
# Open http://deploy-server:8080 in browser
```

## Configuration Reference

### ~/.eventmill/deploy.env

| Variable | Required | Description |
|----------|----------|-------------|
| `GOOGLE_CLOUD_PROJECT` | **Yes** | GCP project ID |
| `EVENTMILL_MODEL_LIGHT` | No | Override the light-tier model id (default from `framework/llm/providers/gcp_gemini.json`) |
| `EVENTMILL_MODEL_HEAVY` | No | Override the heavy-tier model id — useful if the pinned Preview model is retired |
| `EVENTMILL_BUCKET_PREFIX` | No | Bucket naming prefix — must match `provision-gcp-project.sh` (default: `${GOOGLE_CLOUD_PROJECT}-eventmill`) |
| `CLOUD_RUN_REGION` | **Yes** | Deploy region. No default — must match the region you provisioned in, because the Artifact Registry image path embeds it. Every script refuses to guess. |
| `GCS_LOG_BUCKET` | No | Legacy single-bucket override — leave empty for new deployments |
| `EVENTMILL_SECRET_GEMINI_FLASH` | No | Secret Manager name for Flash API key (default: `eventmill-gemini-flash-api`) |
| `EVENTMILL_SECRET_GEMINI_PRO` | No | Secret Manager name for Pro API key (default: `eventmill-gemini-pro-api`) |
| `EVENTMILL_SECRET_TTYD_USER` | No | Secret Manager name for ttyd username (default: `eventmill-ttyd-user`) |
| `EVENTMILL_SECRET_TTYD_CRED` | No | Secret Manager name for ttyd password (default: `eventmill-ttyd-cred`) |
| `EVENTMILL_LOG_LEVEL` | No | Logging level (default: `INFO`) |

### Runtime environment (set by deploy scripts)

| Variable | Description |
|----------|-------------|
| `GEMINI_FLASH_API_KEY` | Gemini Flash API key — light tier (injected from Secret Manager) |
| `GEMINI_PRO_API_KEY` | Gemini Pro API key — heavy tier (injected from Secret Manager) |
| `TTYD_USERNAME` | ttyd basic auth username |
| `TTYD_PASSWORD` | ttyd basic auth password |
| `EVENTMILL_BUCKET_PREFIX` | Bucket prefix for pillar-based storage resolution |
| `GCS_LOG_BUCKET` | Legacy bucket override for log_analysis pillar |
| `GOOGLE_CLOUD_PROJECT` | Auto-set by Cloud Run — used by GCS client for project resolution |
