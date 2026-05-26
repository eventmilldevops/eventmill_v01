#!/bin/bash
# Event Mill v0.1.0 - Cloud Run Deployment Script
# Deploys ttyd web terminal accessible via HTTPS on port 443
#
# Usage:
#   export GOOGLE_CLOUD_PROJECT="your-project-id"
#   export GEMINI_FLASH_API_KEY="your-key"  # light tier (optional)
#   export GEMINI_PRO_API_KEY="your-key"    # heavy tier (optional)
#   bash cloud_install/deploy-cloudrun.sh

set -e

# ---------------------------------------------------------------------------
# Configuration — override via environment variables
# ---------------------------------------------------------------------------
PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-your-project-id}"
REGION="${CLOUD_RUN_REGION:-northamerica-northeast2}"
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
