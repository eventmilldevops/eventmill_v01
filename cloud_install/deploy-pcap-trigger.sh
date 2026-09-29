#!/bin/bash
# =============================================================================
# PCAP Ingest Trigger — Cloud Run function (gen2) deployment
# =============================================================================
#
# Deploys the Phase 1 PCAP ingest trigger: an Eventarc-triggered Cloud Run
# function that fires on new PCAP uploads to the network-forensics bucket
# ("bucket B"), resolves the sensor_id, validates it against the allow-list
# in the common bucket, and writes an acknowledgment marker.
#
# This is a standalone unit — it does not import or invoke any Event Mill
# framework/plugin code. See docs/specs/pcap_ingest_trigger_phase1.md.
#
# Prerequisites:
#   - GOOGLE_CLOUD_PROJECT set
#   - PCAP_TRIGGER_BUCKET set to the network-forensics bucket name
#     (bucket B), e.g. eventmill-network-forensics
#   - gs://<common-bucket>/config/sensors.json exists with the sensor allow-list
#
# Usage:
#   export GOOGLE_CLOUD_PROJECT="your-project-id"
#   export PCAP_TRIGGER_BUCKET="eventmill-network-forensics"
#   bash cloud_install/deploy-pcap-trigger.sh
# =============================================================================

set -e

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-your-project-id}"
REGION="${CLOUD_RUN_REGION:-northamerica-northeast2}"
FUNCTION_NAME="pcap-ingest-trigger"
ENTRY_POINT="handle_pcap_upload"

TRIGGER_BUCKET="${PCAP_TRIGGER_BUCKET:-}"

BUCKET_PREFIX="${EVENTMILL_BUCKET_PREFIX:-eventmill}"
BUCKET_COMMON="${EVENTMILL_BUCKET_COMMON:-${BUCKET_PREFIX}-common}"

# Service account
SA_NAME="pcap-trigger-runner"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

echo "⚙ PCAP Ingest Trigger — Cloud Run Function Deployment"
echo "========================================================"
echo "Project:        ${PROJECT_ID}"
echo "Region:         ${REGION}"
echo "Function:       ${FUNCTION_NAME}"
echo "Trigger bucket: ${TRIGGER_BUCKET}"
echo "Common bucket:  ${BUCKET_COMMON}"
echo "SA:             ${SA_EMAIL}"
echo ""

if [ "${PROJECT_ID}" = "your-project-id" ]; then
    echo "ERROR: Set GOOGLE_CLOUD_PROJECT before running this script."
    exit 1
fi

if [ -z "${TRIGGER_BUCKET}" ]; then
    echo "ERROR: Set PCAP_TRIGGER_BUCKET to the network-forensics bucket name."
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 0: Create the runtime service account (idempotent) and grant
# least-privilege IAM bindings.
# ---------------------------------------------------------------------------
echo "🔑 Ensuring service account ${SA_EMAIL} exists..."

if ! gcloud iam service-accounts describe "${SA_EMAIL}" \
    --project="${PROJECT_ID}" >/dev/null 2>&1; then
    gcloud iam service-accounts create "${SA_NAME}" \
        --project="${PROJECT_ID}" \
        --display-name="PCAP ingest trigger runtime SA"
fi

echo "🔐 Granting least-privilege bucket IAM bindings..."

# Read access to bucket B (pcap objects) and the common bucket (sensors.json).
gcloud storage buckets add-iam-policy-binding "gs://${TRIGGER_BUCKET}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/storage.objectViewer" \
    --project="${PROJECT_ID}" >/dev/null
gcloud storage buckets add-iam-policy-binding "gs://${BUCKET_COMMON}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/storage.objectViewer" \
    --project="${PROJECT_ID}" >/dev/null

# Write access limited to the acks/ prefix in bucket B via an IAM condition.
gcloud storage buckets add-iam-policy-binding "gs://${TRIGGER_BUCKET}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/storage.objectCreator" \
    --condition="expression=resource.name.startsWith(\"projects/_/buckets/${TRIGGER_BUCKET}/objects/acks/\"),title=acks-prefix-only" \
    --project="${PROJECT_ID}" >/dev/null

# ---------------------------------------------------------------------------
# Step 1: Deploy the gen2 Cloud Run function
# ---------------------------------------------------------------------------
echo "🚀 Deploying ${FUNCTION_NAME}..."

gcloud functions deploy "${FUNCTION_NAME}" \
    --project="${PROJECT_ID}" \
    --region="${REGION}" \
    --gen2 \
    --runtime=python312 \
    --source=cloud_install/pcap_trigger \
    --entry-point="${ENTRY_POINT}" \
    --trigger-bucket="${TRIGGER_BUCKET}" \
    --service-account="${SA_EMAIL}" \
    --memory=256Mi \
    --timeout=60s \
    --max-instances=10 \
    --set-env-vars="EVENTMILL_BUCKET_PREFIX=${BUCKET_PREFIX}" \
    --set-env-vars="EVENTMILL_BUCKET_COMMON=${BUCKET_COMMON}"

# ---------------------------------------------------------------------------
# Step 2: Display status
# ---------------------------------------------------------------------------
echo ""
echo "=============================================="
echo "✓ ${FUNCTION_NAME} deployed!"
echo ""
echo "Trigger bucket: gs://${TRIGGER_BUCKET}/"
echo "Sensor registry: gs://${BUCKET_COMMON}/config/sensors.json"
echo "SA: ${SA_EMAIL} (objectViewer on both buckets, objectCreator scoped to acks/)"
echo ""
