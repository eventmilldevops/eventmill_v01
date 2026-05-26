#!/bin/bash
# =============================================================================
# Event Mill v0.1.0 — GCP Project Provisioning
# =============================================================================
#
# Run this script ONCE to prepare a GCP project for Event Mill.
# It is idempotent — safe to re-run if a step fails partway through.
#
# Prerequisites:
#   - gcloud CLI installed and authenticated (gcloud auth login)
#   - A GCP project already created with billing enabled
#   - Sufficient IAM permissions (Owner or Editor on the project)
#
# Usage:
#   export GOOGLE_CLOUD_PROJECT="your-project-id"
#   bash cloud_install/provision-gcp-project.sh
#
# After provisioning, create secrets:
#   bash cloud_install/provision-secrets.sh
#
# Then deploy:
#   bash cloud_install/deploy-cloudrun-secrets.sh
# =============================================================================

set -e

# ---------------------------------------------------------------------------
# Configuration — update these or set via environment variables
# ---------------------------------------------------------------------------

# CHANGE THIS: Your GCP project ID
PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-your-project-id}"

# CHANGE THIS: Deployment region
# See https://cloud.google.com/run/docs/locations for available regions
REGION="${CLOUD_RUN_REGION:-northamerica-northeast2}"

# CHANGE THIS: Bucket prefix for Event Mill storage
# Convention: {prefix}-{pillar-slug} and {prefix}-common
# All bucket names must be globally unique across all of GCP
# Default uses project ID as prefix to guarantee global uniqueness
BUCKET_PREFIX="${EVENTMILL_BUCKET_PREFIX:-${PROJECT_ID}-eventmill}"

# Legacy single-bucket override (backward compatibility)
GCS_LOG_BUCKET="${GCS_LOG_BUCKET:-}"

# Service account name for Event Mill (usually no change needed)
SA_NAME="eventmill-runner"
SA_DISPLAY_NAME="Event Mill Cloud Run Service Account"

# Cloud Run service name (usually no change needed)
SERVICE_NAME="event-mill"

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------

echo "⚙ Event Mill v0.2.0 — GCP Project Provisioning"
echo "================================================="
echo ""
echo "Project:        ${PROJECT_ID}"
echo "Region:         ${REGION}"
echo "Bucket prefix:  ${BUCKET_PREFIX}"
echo "SA:             ${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
echo ""
echo "Buckets to create:"
echo "   ${BUCKET_PREFIX}-log-analysis"
echo "   ${BUCKET_PREFIX}-network-forensics"
echo "   ${BUCKET_PREFIX}-threat-modeling"
echo "   ${BUCKET_PREFIX}-common"
if [ -n "${GCS_LOG_BUCKET}" ]; then
    echo "   (legacy override: ${GCS_LOG_BUCKET} → log-analysis)"
fi
echo ""

if [ "${PROJECT_ID}" = "your-project-id" ]; then
    echo "ERROR: Set GOOGLE_CLOUD_PROJECT before running this script."
    echo "  export GOOGLE_CLOUD_PROJECT=\"your-project-id\""
    exit 1
fi

# Verify gcloud is authenticated and project is accessible
echo "🔍 Verifying project access..."
if ! gcloud projects describe "${PROJECT_ID}" --format="value(projectId)" > /dev/null 2>&1; then
    echo "ERROR: Cannot access project '${PROJECT_ID}'."
    echo "  - Is gcloud authenticated?  gcloud auth login"
    echo "  - Does the project exist?   gcloud projects list"
    exit 1
fi
echo "   OK: Project '${PROJECT_ID}' is accessible."
echo ""

# Capture project number (needed for default compute SA references)
PROJECT_NUMBER=$(gcloud projects describe "${PROJECT_ID}" --format="value(projectNumber)")

# =============================================================================
# Section 1: Enable APIs
# =============================================================================
# These APIs are required for building, deploying, and running Event Mill
# on Cloud Run with GCS artifact storage and Secret Manager.
# API enablement is idempotent — already-enabled APIs are skipped.
# =============================================================================

echo "📡 Section 1: Enabling GCP APIs..."
echo ""

# Cloud Run — hosts the Event Mill container
echo "   Enabling Cloud Run API (run.googleapis.com)..."
gcloud services enable run.googleapis.com --project="${PROJECT_ID}" --quiet

# Cloud Build — builds container images from source
echo "   Enabling Cloud Build API (cloudbuild.googleapis.com)..."
gcloud services enable cloudbuild.googleapis.com --project="${PROJECT_ID}" --quiet

# Artifact Registry — stores built container images
# (Container Registry is deprecated; Artifact Registry is the replacement)
echo "   Enabling Artifact Registry API (artifactregistry.googleapis.com)..."
gcloud services enable artifactregistry.googleapis.com --project="${PROJECT_ID}" --quiet

# Cloud Storage — stores log artifacts and investigation files
echo "   Enabling Cloud Storage API (storage.googleapis.com)..."
gcloud services enable storage.googleapis.com --project="${PROJECT_ID}" --quiet

# Secret Manager — stores API keys, credentials, and ttyd auth
echo "   Enabling Secret Manager API (secretmanager.googleapis.com)..."
gcloud services enable secretmanager.googleapis.com --project="${PROJECT_ID}" --quiet

# Generative Language (Gemini via AI Studio) — AI-powered analysis
# This is the API used by the google-genai Python SDK with GEMINI_API_KEY
echo "   Enabling Generative Language API (generativelanguage.googleapis.com)..."
gcloud services enable generativelanguage.googleapis.com --project="${PROJECT_ID}" --quiet

# Cloud Logging — used by Event Mill for structured audit logging (google-cloud-logging)
echo "   Enabling Cloud Logging API (logging.googleapis.com)..."
gcloud services enable logging.googleapis.com --project="${PROJECT_ID}" --quiet

# API Keys — required for programmatic API key creation and restriction
echo "   Enabling API Keys API (apikeys.googleapis.com)..."
gcloud services enable apikeys.googleapis.com --project="${PROJECT_ID}" --quiet

# IAM — needed for service account and policy management
echo "   Enabling IAM API (iam.googleapis.com)..."
gcloud services enable iam.googleapis.com --project="${PROJECT_ID}" --quiet

echo ""
echo "   ✓ All APIs enabled."
echo ""

# =============================================================================
# Section 2: Service Account
# =============================================================================
# Create a dedicated service account for Event Mill's Cloud Run service.
# This follows the principle of least privilege — the service only gets
# the permissions it needs, rather than using the broad default compute SA.
# =============================================================================

echo "👤 Section 2: Creating service account..."
echo ""

SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

if gcloud iam service-accounts describe "${SA_EMAIL}" --project="${PROJECT_ID}" > /dev/null 2>&1; then
    echo "   ✓ Service account already exists: ${SA_EMAIL}"
else
    gcloud iam service-accounts create "${SA_NAME}" \
        --project="${PROJECT_ID}" \
        --display-name="${SA_DISPLAY_NAME}" \
        --description="Service account for Event Mill Cloud Run deployment" \
        --quiet
    echo "   ✓ Created service account: ${SA_EMAIL}"
fi
echo ""

# =============================================================================
# Section 3: IAM Role Bindings
# =============================================================================
# Grant the Event Mill service account only the permissions it needs.
# Each binding is explained below.
# =============================================================================

echo "🔐 Section 3: Configuring IAM roles..."
echo ""

# Note: Project-level storage.objectUser binding is applied at bucket level instead
# (see Section 4) to avoid conflicts with GCP org policy conditional IAM bindings
# Note: Project-level secretmanager.secretAccessor is not needed — Section 7 applies
# secret-level access which is more granular and bypasses org policy constraints

# Add a project-level IAM binding and fall back to an always-true condition
# for organizations that require conditions on all project IAM bindings.
add_project_binding() {
    local member="$1"
    local role="$2"

    if gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
        --member="${member}" \
        --role="${role}" \
        --quiet > /dev/null 2>&1; then
        return 0
    fi

    if gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
        --member="${member}" \
        --role="${role}" \
        --condition='expression=true,title=eventmill-bootstrap,description=Required for Event Mill bootstrap in condition-enforced IAM projects' \
        --quiet > /dev/null 2>&1; then
        return 0
    fi

    return 1
}

# Allow the SA to write structured logs to Cloud Logging
echo "   Granting Logs Writer..."
if add_project_binding "serviceAccount:${SA_EMAIL}" "roles/logging.logWriter"; then
    echo "   ✓ roles/logging.logWriter"
else
    echo "   ⚠ Could not grant roles/logging.logWriter to ${SA_EMAIL}"
fi

# Allow the SA to submit Cloud Build jobs (Zeek PCAP processing)
echo "   Granting Cloud Build Editor (Zeek integration)..."
if add_project_binding "serviceAccount:${SA_EMAIL}" "roles/cloudbuild.builds.editor"; then
    echo "   ✓ roles/cloudbuild.builds.editor"
else
    echo "   ⚠ Could not grant roles/cloudbuild.builds.editor to ${SA_EMAIL}"
fi

# Allow Cloud Build's default SA to deploy to Cloud Run
# (Cloud Build uses the project's default compute SA for builds)
DEFAULT_COMPUTE_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
CLOUDBUILD_SA="${PROJECT_NUMBER}@cloudbuild.gserviceaccount.com"

# Grant default compute SA access to GCS (Cloud Build uploads source tarballs)
echo "   Granting default compute SA storage access (Cloud Build source upload)..."
if add_project_binding "serviceAccount:${DEFAULT_COMPUTE_SA}" "roles/storage.objectAdmin"; then
    echo "   ✓ roles/storage.objectAdmin for default compute SA"
else
    echo "   ⚠ Could not grant roles/storage.objectAdmin for default compute SA"
fi

# Grant default compute SA permission to push images to Artifact Registry
echo "   Granting default compute SA Artifact Registry write access..."
if add_project_binding "serviceAccount:${DEFAULT_COMPUTE_SA}" "roles/artifactregistry.writer"; then
    echo "   ✓ roles/artifactregistry.writer for default compute SA"
else
    echo "   ⚠ Could not grant roles/artifactregistry.writer for default compute SA"
fi

echo "   Granting Event Mill SA permission to act as default compute SA (Zeek Cloud Build)..."
gcloud iam service-accounts add-iam-policy-binding "${DEFAULT_COMPUTE_SA}" \
    --project="${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/iam.serviceAccountUser" \
    --quiet > /dev/null 2>&1 || true
echo "   ✓ roles/iam.serviceAccountUser on default compute SA for ${SA_NAME}"

echo "   Granting Cloud Build SA permission to deploy to Cloud Run..."
if add_project_binding "serviceAccount:${CLOUDBUILD_SA}" "roles/run.admin"; then
    echo "   ✓ roles/run.admin for Cloud Build SA"
else
    echo "   ⚠ Could not grant roles/run.admin for Cloud Build SA"
fi

echo "   Granting Cloud Build SA permission to act as Event Mill SA..."
gcloud iam service-accounts add-iam-policy-binding "${SA_EMAIL}" \
    --project="${PROJECT_ID}" \
    --member="serviceAccount:${CLOUDBUILD_SA}" \
    --role="roles/iam.serviceAccountUser" \
    --quiet > /dev/null 2>&1 || true
echo "   ✓ roles/iam.serviceAccountUser on ${SA_NAME}"

echo ""

# =============================================================================
# Section 4: GCS Buckets for Investigation Data
# =============================================================================
# Event Mill uses per-pillar buckets for data isolation plus a shared
# common bucket for cross-pillar reference data (e.g. vetted threat intel).
#
# Naming convention:
#   {BUCKET_PREFIX}-log-analysis
#   {BUCKET_PREFIX}-network-forensics
#   {BUCKET_PREFIX}-threat-modeling
#   {BUCKET_PREFIX}-common
#
# Disabled pillars (cloud_investigation, risk_assessment) do not get
# buckets until they are enabled.  Add them here when ready.
#
# Common bucket subdirectory layout (used by threat_report_analyzer):
#   {BUCKET_PREFIX}-common/mitre/               MITRE ATT&CK JSON/STIX bundles
#   {BUCKET_PREFIX}-common/capec/               CAPEC XML/JSON files
#   {BUCKET_PREFIX}-common/cisa/                CISA KEV and advisory files
#   {BUCKET_PREFIX}-common/vendor_advisories/   Vendor security bulletins
#   {BUCKET_PREFIX}-common/threat_actors/       Threat actor profiles
#   {BUCKET_PREFIX}-common/campaigns/           Threat campaign reports
#   {BUCKET_PREFIX}-common/vulnerabilities/     CVE and vulnerability reports
#
# Automated ingestion systems write to the appropriate pillar bucket.
# Which automations write to which buckets is site-specific and managed
# by the implementation team outside of Event Mill.
# =============================================================================

echo "📦 Section 4: Creating GCS buckets for investigation data..."
echo ""

# Lifecycle rule JSON (shared across all pillar buckets)
# CHANGE THIS: Adjust retention period per bucket if needed
cat > /tmp/eventmill-lifecycle-90d.json <<'LIFECYCLE'
{
  "rule": [
    {
      "action": {"type": "Delete"},
      "condition": {"age": 90}
    }
  ]
}
LIFECYCLE

# Common bucket gets longer retention (reference data is curated)
cat > /tmp/eventmill-lifecycle-365d.json <<'LIFECYCLE'
{
  "rule": [
    {
      "action": {"type": "Delete"},
      "condition": {"age": 365}
    }
  ]
}
LIFECYCLE

create_bucket_if_missing() {
    local bucket_name=$1
    local lifecycle_file=$2
    local description=$3

    # Check if bucket already exists and is accessible
    if gcloud storage buckets describe "gs://${bucket_name}" > /dev/null 2>&1; then
        echo "   ✓ Bucket already exists: gs://${bucket_name}"
    else
        if gcloud storage buckets create "gs://${bucket_name}" \
            --project="${PROJECT_ID}" \
            --location="${REGION}" \
            --uniform-bucket-level-access; then
            echo "   ✓ Created bucket: gs://${bucket_name}  (${description})"
        else
            echo ""
            echo "ERROR: Failed to create gs://${bucket_name}."
            echo "Most likely cause: the bucket name is already taken globally."
            echo "Override the prefix and re-run, for example:"
            echo "  export EVENTMILL_BUCKET_PREFIX=${PROJECT_ID}-em2"
            exit 1
        fi
    fi

    # Apply lifecycle rule
    gcloud storage buckets update "gs://${bucket_name}" \
        --project="${PROJECT_ID}" \
        --lifecycle-file="${lifecycle_file}" > /dev/null 2>&1 || true

    # Grant Event Mill SA bucket-level access (storage.objectAdmin)
    # This is applied at bucket level instead of project level to avoid
    # conflicts with GCP org policy conditional IAM bindings
    gcloud storage buckets add-iam-policy-binding "gs://${bucket_name}" \
        --member="serviceAccount:${SA_EMAIL}" \
        --role="roles/storage.objectAdmin" \
        --project="${PROJECT_ID}" \
        --quiet > /dev/null 2>&1 || true
}

# Per-pillar buckets (MVP-enabled pillars only)
create_bucket_if_missing "${BUCKET_PREFIX}-log-analysis"       /tmp/eventmill-lifecycle-90d.json  "log analysis artifacts"
create_bucket_if_missing "${BUCKET_PREFIX}-network-forensics"  /tmp/eventmill-lifecycle-90d.json  "network forensics artifacts"
create_bucket_if_missing "${BUCKET_PREFIX}-threat-modeling"    /tmp/eventmill-lifecycle-90d.json  "threat modeling artifacts"

# Common/shared bucket (longer retention for curated reference data)
create_bucket_if_missing "${BUCKET_PREFIX}-common"             /tmp/eventmill-lifecycle-365d.json "shared cross-pillar data"

# Legacy single-bucket support: if GCS_LOG_BUCKET is set and different
# from the new convention, create it too for backward compatibility
if [ -n "${GCS_LOG_BUCKET}" ] && [ "${GCS_LOG_BUCKET}" != "${BUCKET_PREFIX}-log-analysis" ]; then
    echo ""
    echo "   Legacy bucket override detected: ${GCS_LOG_BUCKET}"
    create_bucket_if_missing "${GCS_LOG_BUCKET}" /tmp/eventmill-lifecycle-90d.json "legacy log bucket"
fi

# ---------------------------------------------------------------------------
# Initialize common bucket folder structure for threat_report_analyzer
# ---------------------------------------------------------------------------
# Creates a .keep placeholder in each subdirectory so the folder hierarchy
# is visible in the GCS console and operators know where to upload reports.
# Each subdirectory maps to a source type in ThreatReportAnalyzer.REPORT_DIRECTORIES.
# ---------------------------------------------------------------------------

init_common_folder() {
    local folder=$1
    local dest="gs://${BUCKET_PREFIX}-common/${folder}/.keep"
    if gsutil ls "${dest}" > /dev/null 2>&1; then
        echo "   ✓ Folder already initialized: gs://${BUCKET_PREFIX}-common/${folder}/"
    else
        echo -n "" | gsutil cp - "${dest}" > /dev/null 2>&1
        echo "   ✓ Initialized folder:         gs://${BUCKET_PREFIX}-common/${folder}/"
    fi
}

echo "   Initializing threat intel folder structure in common bucket..."
for folder in mitre capec cisa vendor_advisories threat_actors campaigns vulnerabilities; do
    init_common_folder "${folder}"
done

# Generated artifacts: tool-produced outputs stored back into the common bucket.
# Convention: common/generated/{tool_name}/{source_relative_path}.summary.md
# Tools read source data from the top-level subdirs above; they write processed
# artifacts here.  Other tools (e.g. risk_assessment_analyzer, log_investigator)
# discover pre-built summaries by scanning common/generated/ instead of re-running
# the LLM.
echo ""
echo "   Initializing generated artifacts namespace in common bucket..."
init_common_folder "generated/threat_report_analyzer"

# Exports: operator-initiated artifact exports via the 'export' CLI command.
# Convention: common/exports/{source_tool}/{filename}
# Per-tool subdirectories are created automatically on first write — only the
# root placeholder is seeded here so the folder is visible in the GCS console.
echo "   Initializing exports namespace in common bucket..."
init_common_folder "exports"

echo ""

# =============================================================================
# Section 5: Artifact Registry
# =============================================================================
# Artifact Registry stores the built Docker images.
# Container Registry (gcr.io) is deprecated — Artifact Registry is the
# supported replacement. Images are pushed to:
#   ${REGION}-docker.pkg.dev/${PROJECT_ID}/eventmill/event-mill
#
# NOTE: Update IMAGE_NAME in deploy scripts to use this path.
# =============================================================================

echo "🐳 Section 5: Artifact Registry..."
echo ""

if gcloud artifacts repositories describe eventmill \
    --project="${PROJECT_ID}" \
    --location="${REGION}" > /dev/null 2>&1; then
    echo "   ✓ Repository already exists: ${REGION}-docker.pkg.dev/${PROJECT_ID}/eventmill"
else
    gcloud artifacts repositories create eventmill \
        --project="${PROJECT_ID}" \
        --repository-format=docker \
        --location="${REGION}" \
        --description="Event Mill container images" \
        --quiet
    echo "   ✓ Created repository: ${REGION}-docker.pkg.dev/${PROJECT_ID}/eventmill"
fi

# =============================================================================
# Section 6: Secret Manager — Create Empty Secrets
# =============================================================================
# Create the secret entries in Secret Manager. Values are added separately
# using provision-secrets.sh (interactive) to avoid storing sensitive
# values in shell history or scripts.
# =============================================================================

echo "🔑 Section 6: Creating Secret Manager entries..."
echo ""

create_secret_if_missing() {
    local secret_name=$1
    local description=$2
    if gcloud secrets describe "${secret_name}" --project="${PROJECT_ID}" > /dev/null 2>&1; then
        echo "   ✓ Secret already exists: ${secret_name}"
    else
        # Create with an empty initial version (placeholder)
        echo -n "placeholder" | gcloud secrets create "${secret_name}" \
            --project="${PROJECT_ID}" \
            --data-file=- \
            --labels="app=eventmill" \
            --quiet
        echo "   ✓ Created secret: ${secret_name} (placeholder value — update via provision-secrets.sh)"
    fi
}

# Gemini API keys — separate keys per model tier to isolate quota
# Flash key handles high-volume light tasks (log scanning, pattern discovery)
# Pro key handles deep reasoning tasks (threat modeling, attack paths)
create_secret_if_missing "eventmill-gemini-flash-api" "Gemini Flash API key (light tier)"
create_secret_if_missing "eventmill-gemini-pro-api" "Gemini Pro API key (heavy tier)"

# GCS service account key — JSON key file for GCS bucket access
# NOTE: Only needed if NOT using workload identity or the default compute SA
create_secret_if_missing "eventmill-gcs-sa" "GCS service account key JSON"

# ttyd web terminal credentials — basic auth for the browser-based shell
create_secret_if_missing "eventmill-ttyd-user" "ttyd web terminal username"
create_secret_if_missing "eventmill-ttyd-cred" "ttyd web terminal password"

echo ""

# =============================================================================
# Section 7: Grant Event Mill SA Access to Its Secrets
# =============================================================================
# Cloud Run needs to read secrets at container startup.
# Grant secret-level access to the Event Mill service account.
# =============================================================================

echo "🔗 Section 7: Binding secrets to service account..."
echo ""

bind_secret_to_sa() {
    local secret_name=$1
    gcloud secrets add-iam-policy-binding "${secret_name}" \
        --project="${PROJECT_ID}" \
        --member="serviceAccount:${SA_EMAIL}" \
        --role="roles/secretmanager.secretAccessor" \
        --quiet > /dev/null 2>&1
    echo "   ✓ ${SA_NAME} can read ${secret_name}"
}

bind_secret_to_sa "eventmill-gemini-flash-api"
bind_secret_to_sa "eventmill-gemini-pro-api"
bind_secret_to_sa "eventmill-gcs-sa"
bind_secret_to_sa "eventmill-ttyd-user"
bind_secret_to_sa "eventmill-ttyd-cred"

# Also grant the default compute SA (used by Cloud Build during deploy)
echo ""
echo "   Granting default compute SA access to secrets (for Cloud Build)..."
bind_secret_to_default() {
    local secret_name=$1
    gcloud secrets add-iam-policy-binding "${secret_name}" \
        --project="${PROJECT_ID}" \
        --member="serviceAccount:${DEFAULT_COMPUTE_SA}" \
        --role="roles/secretmanager.secretAccessor" \
        --quiet > /dev/null 2>&1
    echo "   ✓ default-compute can read ${secret_name}"
}

bind_secret_to_default "eventmill-gemini-flash-api"
bind_secret_to_default "eventmill-gemini-pro-api"
bind_secret_to_default "eventmill-gcs-sa"
bind_secret_to_default "eventmill-ttyd-user"
bind_secret_to_default "eventmill-ttyd-cred"

echo ""

# =============================================================================
# Section 8: Summary and Next Steps
# =============================================================================

echo "================================================="
echo "✅ GCP project provisioning complete!"
echo "================================================="
echo ""
echo "Project:          ${PROJECT_ID}"
echo "Region:           ${REGION}"
echo "Service Account:  ${SA_EMAIL}"
echo "Bucket prefix:    ${BUCKET_PREFIX}"
echo "Artifact Reg:     ${REGION}-docker.pkg.dev/${PROJECT_ID}/eventmill"
echo ""
echo "Storage buckets:"
echo "   gs://${BUCKET_PREFIX}-log-analysis              (log analysis)"
echo "   gs://${BUCKET_PREFIX}-network-forensics         (network forensics)"
echo "   gs://${BUCKET_PREFIX}-threat-modeling           (threat modeling)"
echo "   gs://${BUCKET_PREFIX}-common                    (shared reference data)"
echo "   gs://${BUCKET_PREFIX}-common/generated/         (tool-generated artifacts)"
echo "   gs://${BUCKET_PREFIX}-common/generated/threat_report_analyzer/"
echo "   gs://${BUCKET_PREFIX}-common/exports/           (operator exports via 'export' CLI command)"
echo "   gs://${BUCKET_PREFIX}-common/exports/<tool>/    (created on first write per tool)"
echo ""
echo "Secrets created (placeholder values):"
echo "   - eventmill-gemini-flash-api  (Flash / light tier)"
echo "   - eventmill-gemini-pro-api    (Pro / heavy tier)"
echo "   - eventmill-gcs-sa"
echo "   - eventmill-ttyd-user"
echo "   - eventmill-ttyd-cred"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "NEXT STEPS:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  1. Add real secret values:"
echo "     bash cloud_install/provision-secrets.sh"
echo ""
echo "  2. Deploy Event Mill:"
echo "     export EVENTMILL_BUCKET_PREFIX=${BUCKET_PREFIX}"
echo "     bash cloud_install/deploy-cloudrun-secrets.sh"
echo ""
echo "  3. Upload files to the appropriate pillar bucket:"
echo "     gsutil cp /path/to/logs/*.log gs://${BUCKET_PREFIX}-log-analysis/"
echo "     gsutil cp /path/to/pcaps/*.pcap gs://${BUCKET_PREFIX}-network-forensics/"
echo ""
echo "  4. Upload threat intelligence reports to common bucket (by source type):"
echo "     gsutil cp /path/to/attack.json                   gs://${BUCKET_PREFIX}-common/mitre/"
echo "     gsutil cp /path/to/capec.xml                    gs://${BUCKET_PREFIX}-common/capec/"
echo "     gsutil cp /path/to/cisa-advisory.json           gs://${BUCKET_PREFIX}-common/cisa/"
echo "     gsutil cp /path/to/vendor-bulletin.pdf          gs://${BUCKET_PREFIX}-common/vendor_advisories/"
echo "     gsutil cp /path/to/actor-profile.json           gs://${BUCKET_PREFIX}-common/threat_actors/"
echo "     gsutil cp /path/to/campaign-report.md           gs://${BUCKET_PREFIX}-common/campaigns/"
echo "     gsutil cp /path/to/cve-report.json              gs://${BUCKET_PREFIX}-common/vulnerabilities/"
echo ""
echo "  5. Use workspace folders to organize by incident:"
echo "     gsutil cp /path/to/logs/*.log gs://${BUCKET_PREFIX}-log-analysis/incident-2024-03/"
echo ""
