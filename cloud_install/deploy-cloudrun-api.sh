#!/bin/bash
# =============================================================================
# Event Mill Headless API — Cloud Run deployment
# =============================================================================
#
# Deploys the same Event Mill image used by deploy-cloudrun.sh as a SECOND,
# separate Cloud Run service ("event-mill-api") running the headless HTTP
# API (framework/cli/api_server.py) instead of the interactive ttyd shell.
#
# This is Phase 2 of the PCAP ingest pipeline — see
# docs/specs/pcap_ingest_trigger_phase2.md. The interactive "event-mill"
# service deployed by deploy-cloudrun.sh is completely unaffected; this is
# an additive second deployment of the same codebase.
#
# The service is NOT publicly accessible — only the pcap_trigger function's
# runtime service account is granted roles/run.invoker on it.
#
# Prerequisites:
#   - GOOGLE_CLOUD_PROJECT set
#   - The image built by build-event-mill.yaml already exists (run
#     deploy-cloudrun.sh at least once, or `gcloud builds submit
#     --config=build-event-mill.yaml .` directly)
#   - GEMINI_FLASH_API_KEY / GEMINI_PRO_API_KEY set for LLM-backed tools
#
# Usage:
#   export GOOGLE_CLOUD_PROJECT="your-project-id"
#   export GEMINI_FLASH_API_KEY="your-key"
#   export GEMINI_PRO_API_KEY="your-key"
#   bash cloud_install/deploy-cloudrun-api.sh
# =============================================================================

set -e

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-your-project-id}"
REGION="${CLOUD_RUN_REGION:-northamerica-northeast2}"
SERVICE_NAME="event-mill-api"
AR_REPO="${EVENTMILL_AR_REPO:-eventmill}"
IMAGE_NAME="${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPO}/event-mill:latest"

# The pcap_trigger function's runtime SA (created by deploy-pcap-trigger.sh)
# is the only identity granted permission to call this service.
PCAP_TRIGGER_SA="${PCAP_TRIGGER_SA:-pcap-trigger-runner@${PROJECT_ID}.iam.gserviceaccount.com}"

echo "⚙ Event Mill Headless API — Cloud Run Deployment"
echo "===================================================="
echo "Project:  ${PROJECT_ID}"
echo "Region:   ${REGION}"
echo "Service:  ${SERVICE_NAME}"
echo "Caller:   ${PCAP_TRIGGER_SA}"
echo ""

if [ "${PROJECT_ID}" = "your-project-id" ]; then
    echo "ERROR: Set GOOGLE_CLOUD_PROJECT before running this script."
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 1: Deploy to Cloud Run (same image as event-mill, api mode)
# ---------------------------------------------------------------------------
echo "🚀 Deploying ${SERVICE_NAME}..."
gcloud run deploy "${SERVICE_NAME}" \
    --project="${PROJECT_ID}" \
    --region="${REGION}" \
    --image="${IMAGE_NAME}" \
    --platform=managed \
    --command="python" \
    --args="-m,framework.cli.api_server" \
    --port=8080 \
    --memory=2Gi \
    --cpu=2 \
    --min-instances=0 \
    --max-instances=5 \
    --timeout=900 \
    --concurrency=1 \
    --set-env-vars="EVENTMILL_MODE=api" \
    --set-env-vars="GOOGLE_CLOUD_PROJECT=${PROJECT_ID}" \
    --set-env-vars="GEMINI_FLASH_API_KEY=${GEMINI_FLASH_API_KEY:-}" \
    --set-env-vars="GEMINI_PRO_API_KEY=${GEMINI_PRO_API_KEY:-}" \
    --set-env-vars="ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}" \
    --set-env-vars="EVENTMILL_BUCKET_PREFIX=${EVENTMILL_BUCKET_PREFIX:-${PROJECT_ID}-eventmill}" \
    --set-env-vars="EVENTMILL_LOG_LEVEL=${EVENTMILL_LOG_LEVEL:-INFO}" \
    --no-allow-unauthenticated

# ---------------------------------------------------------------------------
# Step 2: Grant the pcap_trigger function's SA permission to invoke it
# ---------------------------------------------------------------------------
echo ""
echo "🔐 Granting run.invoker to ${PCAP_TRIGGER_SA}..."
gcloud run services add-iam-policy-binding "${SERVICE_NAME}" \
    --project="${PROJECT_ID}" \
    --region="${REGION}" \
    --member="serviceAccount:${PCAP_TRIGGER_SA}" \
    --role="roles/run.invoker" >/dev/null

# ---------------------------------------------------------------------------
# Step 3: Display results
# ---------------------------------------------------------------------------
echo ""
SERVICE_URL=$(gcloud run services describe "${SERVICE_NAME}" \
    --project="${PROJECT_ID}" \
    --region="${REGION}" \
    --format="value(status.url)")

echo "✅ ${SERVICE_NAME} deployed!"
echo ""
echo "URL (authenticated callers only): ${SERVICE_URL}"
echo "Endpoints: POST /analyze   GET /healthz"
echo ""
echo "Note: the existing interactive 'event-mill' (ttyd) service is"
echo "unaffected by this deployment."
