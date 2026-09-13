#!/bin/bash
# Event Mill v0.1.0 - Cloud Run Deployment Script
# Deploys ttyd web terminal accessible via HTTPS on port 443
#
# Usage:
#   export GOOGLE_CLOUD_PROJECT="your-project-id"
#   export CLOUD_RUN_REGION="us-central1"
#
#   # Gemini — the default provider. Light and heavy tiers are keyed
#   # separately so bulk Flash work cannot consume Pro quota.
#   export GEMINI_FLASH_API_KEY="your-key"  # light tier (optional)
#   export GEMINI_PRO_API_KEY="your-key"    # heavy tier (optional)
#
#   # Anthropic / OpenAI — one key per provider. Neither vendor splits keys
#   # by tier, so a single key serves both tiers of that provider.
#   export ANTHROPIC_API_KEY="your-key"     # (optional)
#   export OPENAI_API_KEY="your-key"        # (optional)
#
#   bash cloud_install/deploy-cloudrun.sh
#
# Every key is passed explicitly, empty when unset. Passing an empty value
# rather than omitting the flag means a redeploy without a key CLEARS it —
# omitting it would leave whatever the previous revision had, which is how a
# rotated-out key keeps working and nobody notices.
#
# NOTE: this is the plain-env-var path, for quick tests. Keys land in the
# Cloud Run service config in clear text, readable by anyone holding
# run.services.get. Production uses deploy-cloudrun-secrets.sh, which mounts
# them from Secret Manager instead (see the warning printed at the end).

set -e

# ---------------------------------------------------------------------------
# Configuration — override via environment variables
# ---------------------------------------------------------------------------
PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-your-project-id}"
REGION="${CLOUD_RUN_REGION:-}"
SERVICE_NAME="event-mill"
IMAGE_NAME="${REGION}-docker.pkg.dev/${PROJECT_ID}/eventmill/${SERVICE_NAME}"

echo "⚙ Event Mill v0.1.0 — Cloud Run Deployment"
echo "============================================="
echo "Project:  ${PROJECT_ID}"
echo "Region:   ${REGION}"
echo "Service:  ${SERVICE_NAME}"
echo ""

if [ "${PROJECT_ID}" = "your-project-id" ]; then
    echo "ERROR: Set GOOGLE_CLOUD_PROJECT before running this script."
    exit 1
fi

# Region is never guessed: the Artifact Registry image path embeds it, so
# provisioning in one region and deploying in another fails at push time.
if [ -z "${REGION}" ]; then
    echo "ERROR: Set CLOUD_RUN_REGION before running this script."
    echo "  It must match the region you provisioned in."
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 1: Enable required APIs
# ---------------------------------------------------------------------------
echo "📡 Enabling required APIs..."
gcloud services enable run.googleapis.com --project="${PROJECT_ID}" --quiet
gcloud services enable cloudbuild.googleapis.com --project="${PROJECT_ID}" --quiet

# ---------------------------------------------------------------------------
# Step 1b: Grant Event Mill SA permission to act as default compute SA
#          Required for Zeek Cloud Build job submission
# ---------------------------------------------------------------------------
echo ""
echo "🔧 Granting Event Mill SA permission to act as default compute SA (Zeek Cloud Build)..."
SA_NAME="eventmill-runner"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
PROJECT_NUMBER=$(gcloud projects describe "${PROJECT_ID}" --format="value(projectNumber)")
DEFAULT_COMPUTE_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
gcloud iam service-accounts add-iam-policy-binding "${DEFAULT_COMPUTE_SA}" \
    --project="${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/iam.serviceAccountUser" \
    --quiet > /dev/null 2>&1 || true
echo "   OK: roles/iam.serviceAccountUser on default compute SA for ${SA_NAME}"

# ---------------------------------------------------------------------------
# Step 1c: Report which LLM keys this deploy will carry
# ---------------------------------------------------------------------------
# Presence only — never the value, never a prefix of it. The 3.8 model swap
# was correct in the source and inert in the environment for a whole session
# because nothing announced what was actually configured. Three vendors have
# strictly more ways to be half-applied, so the deploy says what it is doing
# before it does it.
# ---------------------------------------------------------------------------
echo ""
echo "🔑 LLM keys in this deploy:"
key_state() {
    # $1 = env var name
    if [ -n "${!1:-}" ]; then echo "set"; else echo "not set"; fi
}
for var in GEMINI_FLASH_API_KEY GEMINI_PRO_API_KEY ANTHROPIC_API_KEY OPENAI_API_KEY; do
    printf '   %-22s %s\n' "${var}" "$(key_state "${var}")"
done

if [ -z "${GEMINI_FLASH_API_KEY:-}" ] && [ -z "${GEMINI_PRO_API_KEY:-}" ] \
   && [ -z "${GEMINI_API_KEY:-}" ]; then
    echo ""
    echo "   ⚠  No Gemini key set. Gemini is currently the ONLY provider the"
    echo "      runtime binds, so 'connect' will find no models."
fi

if [ -n "${ANTHROPIC_API_KEY:-}" ] || [ -n "${OPENAI_API_KEY:-}" ]; then
    echo ""
    echo "   ℹ  Anthropic / OpenAI keys are carried into the container, but the"
    echo "      runtime does not bind them yet — model discovery still reads"
    echo "      only framework/llm/providers/gcp_gemini.json. Until the"
    echo "      provider registry lands, verify them with 'printenv' in the"
    echo "      terminal, not with 'models' or 'connect'."
    echo "      Plan: docs/specs/multi_provider_llm_clients.md (Stages 2 and 5)"
fi

# ---------------------------------------------------------------------------
# Step 2: Build the container image
# ---------------------------------------------------------------------------
echo ""
echo "📦 Building container image..."
gcloud builds submit \
    --project="${PROJECT_ID}" \
    --config=build-event-mill.yaml \
    --substitutions="_REGION=${REGION}" \
    .

# ---------------------------------------------------------------------------
# Step 3: Deploy to Cloud Run
# ---------------------------------------------------------------------------
echo ""
echo "🚀 Deploying to Cloud Run..."
gcloud run deploy "${SERVICE_NAME}" \
    --project="${PROJECT_ID}" \
    --region="${REGION}" \
    --image="${IMAGE_NAME}" \
    --platform=managed \
    --port=8080 \
    --memory=2Gi \
    --cpu=2 \
    --no-cpu-throttling \
    --min-instances=0 \
    --max-instances=3 \
    --timeout=3600 \
    --concurrency=5 \
    --session-affinity \
    --set-env-vars="GOOGLE_CLOUD_PROJECT=${PROJECT_ID}" \
    --set-env-vars="GEMINI_FLASH_API_KEY=${GEMINI_FLASH_API_KEY:-}" \
    --set-env-vars="GEMINI_PRO_API_KEY=${GEMINI_PRO_API_KEY:-}" \
    --set-env-vars="ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}" \
    --set-env-vars="OPENAI_API_KEY=${OPENAI_API_KEY:-}" \
    --set-env-vars="EVENTMILL_LLM_PROVIDERS=${EVENTMILL_LLM_PROVIDERS:-gcp_gemini}" \
    --set-env-vars="EVENTMILL_BUCKET_PREFIX=${EVENTMILL_BUCKET_PREFIX:-${PROJECT_ID}-eventmill}" \
    --set-env-vars="GCS_LOG_BUCKET=${GCS_LOG_BUCKET:-}" \
    --set-env-vars="EVENTMILL_LOG_LEVEL=${EVENTMILL_LOG_LEVEL:-INFO}" \
    --set-env-vars="TTYD_USERNAME=${TTYD_USERNAME:-admin}" \
    --set-env-vars="TTYD_PASSWORD=${TTYD_PASSWORD:-changeme}" \
    --allow-unauthenticated

# Note: For authenticated access, replace --allow-unauthenticated with:
#   --no-allow-unauthenticated
# Then grant access via IAM:
#   gcloud run services add-iam-policy-binding event-mill \
#       --region="${REGION}" \
#       --member="user:you@example.com" \
#       --role="roles/run.invoker"

# ---------------------------------------------------------------------------
# Step 4: Display results
# ---------------------------------------------------------------------------
echo ""
echo "✅ Deployment complete!"
echo ""

SERVICE_URL=$(gcloud run services describe "${SERVICE_NAME}" \
    --project="${PROJECT_ID}" \
    --region="${REGION}" \
    --format="value(status.url)")

echo "🌐 Event Mill is available at:"
echo "   ${SERVICE_URL}"
echo ""
echo "   Cloud Run provides HTTPS on port 443 automatically."
echo "   The ttyd terminal is accessible directly at the URL above."
echo ""
echo "⚠  WARNING: Secrets are passed as env vars in this mode."
echo "   For production, use deploy-cloudrun-secrets.sh instead."
