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

For a new project, complete [GCP provisioning](#gcp-project-provisioning-first-time-only)
and [provider and secret setup](#secret-manager-setup) before deploying.

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
export ANTHROPIC_API_KEY="your-anthropic-key"
export OPENAI_API_KEY="your-openai-key"
export EVENTMILL_LLM_PROVIDERS="gcp_gemini anthropic openai"
export TTYD_USERNAME="admin"
export TTYD_PASSWORD="changeme"
cd ~/eventmill_v01
bash cloud_install/deploy-cloudrun.sh
```

The example enables all three providers. Omit key exports for providers you do
not use; at least one provider needs a real key. For production, use the hidden
input and Secret Manager workflow below instead of placing keys in commands.

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
| `_LLM_PROVIDERS` | `gcp_gemini anthropic openai openai_daybreak_red openai_daybreak_blue` | Space-separated provider IDs. Set to `gcp_gemini anthropic openai` for the three-provider setup in this guide. |

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

# 2. Follow "Secret Manager Setup" below to obtain and store provider keys
#    and set the ttyd credentials before deploying.
```

This creates everything the project needs: APIs enabled (including
`apikeys.googleapis.com` for key creation and `logging.googleapis.com` for
audit logging), a dedicated service account with least-privilege IAM roles,
GCS buckets (per-pillar + common) with lifecycle rules, Artifact Registry,
and Secret Manager entries for Gemini, Anthropic, OpenAI, optional Daybreak,
and ttyd credentials. Provisioning creates secret entries; follow
[Secret Manager Setup](#secret-manager-setup) to supply usable credentials.

Provisioning is the **only** place IAM is written. The deploy scripts merely
verify, so the deploy path needs no `*.setIamPolicy` permission and can run
under a CI service account that must not be able to rewrite IAM.

When it finishes it prints the exact `~/.eventmill/deploy.env` to save, with
the resolved project, region and bucket prefix filled in. The provisioning and
deploy scripts both read that file automatically on subsequent runs.

## LLM Models

The Cloud Run image already installs the SDKs for **Google Gemini, Anthropic
Claude, and OpenAI**. No separate provider package installation is needed.
Setup consists of obtaining API keys, storing them in Secret Manager, deploying,
and selecting a provider in the Event Mill shell.

Each provider has light and heavy tiers. The manifests are the source of truth
for this checkout's configured models, limits, and capabilities:

| Provider ID | Manifest | Credentials used by Event Mill |
|---|---|---|
| `gcp_gemini` | [gcp_gemini.json](../framework/llm/providers/gcp_gemini.json) | `GEMINI_FLASH_API_KEY` for light; `GEMINI_PRO_API_KEY` for heavy |
| `anthropic` | [anthropic.json](../framework/llm/providers/anthropic.json) | `ANTHROPIC_API_KEY` for both tiers |
| `openai` | [openai.json](../framework/llm/providers/openai.json) | `OPENAI_API_KEY` for both tiers |

Light is generally used for bulk extraction and summarization; heavy for threat
modeling, synthesis, and `ask:`. Each plugin declares its default `model_tier`.
Limits and document support vary by provider. Confirm your account can access
the configured models using the probes below. Automatic fallback stays within
the selected provider; it never silently sends work to another vendor.

Event Mill uses separate Gemini key variables for its two tiers. Separate keys
in the same project do **not** create independent quotas: Google's
[rate limits apply per project](https://ai.google.dev/gemini-api/docs/rate-limits).

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

### 1. Obtain API keys

You need API access and sufficient billing/credits for each provider you intend
to use. GCP authentication gives the deploy scripts access to cloud resources;
it does not supply Anthropic or OpenAI API credentials.

- **Gemini:** create keys for your project in Google AI Studio following
  [Google's API key guide](https://ai.google.dev/gemini-api/docs/api-key).
  Store a key for each of Event Mill's light and heavy tier secrets below.
- **Anthropic:** in the Claude Console, open **Settings → API keys** and
  create a key for the intended workspace. Event Mill uses that key for both
  tiers. See [Anthropic authentication](https://platform.claude.com/docs/en/manage-claude/authentication).
- **OpenAI:** create an API key in the OpenAI developer dashboard for the
  intended project, following the [OpenAI quickstart](https://developers.openai.com/api/docs/quickstart).
  Event Mill uses that key for both tiers.

### 2. Store credentials in Secret Manager

Run `provision-gcp-project.sh` first so the entries and IAM grants exist.
These are the default mappings:

| Provider / purpose | Secret Manager name | Container environment variable |
|---|---|---|
| Gemini light | `eventmill-gemini-flash-api` | `GEMINI_FLASH_API_KEY` |
| Gemini heavy | `eventmill-gemini-pro-api` | `GEMINI_PRO_API_KEY` |
| Anthropic, both tiers | `eventmill-anthropic-api` | `ANTHROPIC_API_KEY` |
| OpenAI, both tiers | `eventmill-openai-api` | `OPENAI_API_KEY` |
| Terminal username | `eventmill-ttyd-user` | `TTYD_USERNAME` |
| Terminal password | `eventmill-ttyd-cred` | `TTYD_PASSWORD` |

The interactive helper is available on the Linux deploy server:

```bash
cd ~/eventmill_v01
source ~/.eventmill/deploy.env
export GOOGLE_CLOUD_PROJECT
bash cloud_install/provision-secrets.sh
```

The helper attempts to create restricted Gemini keys first. It then asks
whether to update Anthropic and OpenAI: answer `y` and paste the corresponding
key at each hidden prompt. Answer `n` for providers you do not use. Skip the
optional Daybreak credential unless you have separate access, and skip the GCS
service-account JSON prompt for Cloud Run's workload identity setup. Set both
ttyd credentials to real values.

**Gemini helper limitation:** it currently creates standard Google API keys via
`gcloud services api-keys create`. Google's [key migration guidance](https://ai.google.dev/gemini-api/docs/api-key)
announces rejection of standard keys in September 2026. For a new installation,
use AI Studio's current key creation flow and the manual entry method below.
The helper also uses fixed secret names and does not load `deploy.env` itself;
use the manual method for custom secret names or to configure only OpenAI or
Anthropic without running its Gemini creation steps.

Run this Bash function on the deploy server, then call it for each credential
you want to set. Values are entered without echoing or putting them in shell
history. Replace names if you use custom secrets.

```bash
source ~/.eventmill/deploy.env
store_eventmill_secret() {
    local secret_value
    read -r -s -p "Value for $1: " secret_value
    printf '\n'
    if [ -z "$secret_value" ]; then
        printf 'Empty value; nothing saved.\n' >&2
        return 1
    fi
    printf '%s' "$secret_value" | gcloud secrets versions add "$1" \
        --project="${GOOGLE_CLOUD_PROJECT}" --data-file=-
}

store_eventmill_secret eventmill-gemini-flash-api
store_eventmill_secret eventmill-gemini-pro-api
store_eventmill_secret eventmill-anthropic-api
store_eventmill_secret eventmill-openai-api
store_eventmill_secret eventmill-ttyd-user
store_eventmill_secret eventmill-ttyd-cred
```

Call only the provider entries you intend to use; always set the ttyd pair.
Unused provider secrets may retain `placeholder`. Keep the provisioned entries:
the deployment mounts them even when the provider is dormant. At least one LLM
provider needs a real key. A non-placeholder value is not proof of API access;
verify it after deployment.

### 3. Enable providers and deploy

For the three providers covered here, add this line to `~/.eventmill/deploy.env`:

```bash
export EVENTMILL_LLM_PROVIDERS="gcp_gemini anthropic openai"
```

If an older config lists only `gcp_gemini`, update it or the other providers will
not bind. The scripts' built-in default also includes `openai_daybreak_red` and
`openai_daybreak_blue`; those are optional OpenAI profiles using a separate
credential, not requirements for the standard `openai` provider. Cloud Build
uses `_LLM_PROVIDERS` instead of reading this file.

```bash
source ~/.eventmill/deploy.env
cd ~/eventmill_v01
bash cloud_install/deploy-cloudrun-secrets.sh
```

Use the same sequence after adding or rotating a key. A new secret version does
not update the environment of an already-running container; redeploy and open
a new terminal session. The normal deploy script rebuilds the image as part of
its workflow, although changing a key requires no application code changes.

### 4. Verify and select providers

Open the deployed URL and sign in with your ttyd credentials. Run the following
inside the **Event Mill shell**, not in Bash:

```text
providers
connect
models
providers probe gcp_gemini
providers probe anthropic
providers probe openai
```

Probe only the providers you configured. `connect` constructs clients without
making API calls; each probe performs model discovery and a small completion
request, which can incur usage charges. Check that both tiers succeed.

Choose a session default or override one tool:

```text
use openai
use anthropic for threat_model_analyzer
use gcp_gemini for threat_report_analyzer
use
```

Selections last for the current session. `ask:` follows the session default;
per-tool overrides apply to that tool only.

| Symptom | Check |
|---|---|
| Provider is dormant or missing from `models` | Its key is missing or `placeholder`, its ID is absent from `EVENTMILL_LLM_PROVIDERS`, or the session predates the redeployment. |
| `connect` succeeds but a probe fails | Read the probe error; check key validity, API billing/credits, permissions, and access to the manifest's models. |
| Secret is missing or access is denied during deployment | Run project provisioning and check the configured secret name and runtime service account's access. |

See the [multi-provider design](../docs/specs/multi_provider_llm_clients.md)
for routing details.

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

For a local test with all three providers, set the following. Omit unused
provider key exports; at least one provider needs a real key.

```bash
export GOOGLE_CLOUD_PROJECT="your-project-id"
export EVENTMILL_BUCKET_PREFIX="${GOOGLE_CLOUD_PROJECT}-eventmill"   # default — matches provision-gcp-project.sh
export GEMINI_FLASH_API_KEY="your-flash-key"
export GEMINI_PRO_API_KEY="your-pro-key"
export ANTHROPIC_API_KEY="your-anthropic-key"
export OPENAI_API_KEY="your-openai-key"
export EVENTMILL_LLM_PROVIDERS="gcp_gemini anthropic openai"
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
| `EVENTMILL_MAX_OUTPUT_LIGHT` / `EVENTMILL_MAX_OUTPUT_HEAVY` | No | Output-token cap for a tier whose model was overridden above. Set it with the model override: the cap otherwise still comes from the manifest, and clamping against the wrong one fails at the provider |
| `EVENTMILL_BUCKET_PREFIX` | No | Bucket naming prefix — must match `provision-gcp-project.sh` (default: `${GOOGLE_CLOUD_PROJECT}-eventmill`) |
| `CLOUD_RUN_REGION` | **Yes** | Deploy region. No default — must match the region you provisioned in, because the Artifact Registry image path embeds it. Every script refuses to guess. |
| `GCS_LOG_BUCKET` | No | Legacy single-bucket override — leave empty for new deployments |
| `EVENTMILL_LLM_PROVIDERS` | No | Space-separated provider IDs. Script default: `gcp_gemini anthropic openai openai_daybreak_red openai_daybreak_blue`. This guide explicitly selects the first three. Missing or `placeholder` keys stay dormant; unknown IDs are refused. |
| `EVENTMILL_SECRET_GEMINI_FLASH` | No | Secret Manager name for Flash API key (default: `eventmill-gemini-flash-api`) |
| `EVENTMILL_SECRET_GEMINI_PRO` | No | Secret Manager name for Pro API key (default: `eventmill-gemini-pro-api`) |
| `EVENTMILL_SECRET_ANTHROPIC` | No | Secret Manager name for the Anthropic API key (default: `eventmill-anthropic-api`) |
| `EVENTMILL_SECRET_OPENAI` | No | Secret Manager name for the OpenAI API key (default: `eventmill-openai-api`) |
| `EVENTMILL_SECRET_TTYD_USER` | No | Secret Manager name for ttyd username (default: `eventmill-ttyd-user`) |
| `EVENTMILL_SECRET_TTYD_CRED` | No | Secret Manager name for ttyd password (default: `eventmill-ttyd-cred`) |
| `EVENTMILL_LOG_LEVEL` | No | Logging level (default: `INFO`) |

### Runtime environment (set by deploy scripts)

| Variable | Description |
|----------|-------------|
| `GEMINI_FLASH_API_KEY` | Gemini Flash API key — light tier (injected from Secret Manager) |
| `GEMINI_PRO_API_KEY` | Gemini Pro API key — heavy tier (injected from Secret Manager) |
| `ANTHROPIC_API_KEY` | Anthropic API key (injected from Secret Manager; `placeholder` until adopted) |
| `OPENAI_API_KEY` | OpenAI API key (injected from Secret Manager; `placeholder` until adopted) |
| `EVENTMILL_LLM_PROVIDERS` | Providers this deployment may bind; script defaults include the three standard providers and two optional Daybreak profiles. Unkeyed providers stay dormant. |
| `TTYD_USERNAME` | ttyd basic auth username |
| `TTYD_PASSWORD` | ttyd basic auth password |
| `EVENTMILL_BUCKET_PREFIX` | Bucket prefix for pillar-based storage resolution |
| `GCS_LOG_BUCKET` | Legacy bucket override for log_analysis pillar |
| `GOOGLE_CLOUD_PROJECT` | Auto-set by Cloud Run — used by GCS client for project resolution |

### Artifact export

`workspace/artifacts` in the container is ephemeral. The `export` command
copies session artifacts to the common bucket under
`exports/<source_tool>/[<subfolder>/]<filename>`:

```
export <artifact_id> [subfolder]
export --all [subfolder]          # every tool-produced artifact in the session
```

On Cloud Run (detected via `K_SERVICE`) outputs of `attack_path_visualizer`
are exported automatically after each run. Two optional variables tune this:

| Variable | Default | Effect |
|---|---|---|
| `EVENTMILL_AUTO_EXPORT_TOOLS` | `attack_path_visualizer` | Comma-separated tool names to auto-export; `*` for all, empty string to disable |
| `EVENTMILL_AUTO_EXPORT` | unset | Set to `1` to enable auto-export outside Cloud Run (local testing) |

Download exported files with `gcloud storage cp gs://<prefix>-common/exports/... .`
