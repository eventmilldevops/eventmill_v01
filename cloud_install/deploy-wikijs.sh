#!/bin/bash
# =============================================================================
# Wiki.js — Cloud Run Deployment
# =============================================================================
#
# Builds and deploys Wiki.js to Cloud Run with Cloud SQL PostgreSQL.
# Uses Cloud SQL Auth Proxy (built into Cloud Run) for secure DB access.
#
# Prerequisites:
#   - provision-wikijs.sh has been run
#   - GOOGLE_CLOUD_PROJECT set
#
# Usage:
#   export GOOGLE_CLOUD_PROJECT="your-project-id"
#   bash cloud_install/deploy-wikijs.sh
# =============================================================================

set -e

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-your-project-id}"
REGION="${CLOUD_RUN_REGION:-northamerica-northeast2}"
SERVICE_NAME="wikijs"
IMAGE_NAME="${REGION}-docker.pkg.dev/${PROJECT_ID}/eventmill/${SERVICE_NAME}"

# Cloud SQL
SQL_INSTANCE_NAME="${WIKIJS_SQL_INSTANCE:-wikijs-db}"
SQL_DB_NAME="wikijs"

# Secret
SECRET_DB_USERNAME="${WIKIJS_SECRET_DB_USERNAME:-wikijs-db-user}"
SECRET_DB_PASSWORD="wikijs-db-password"

# Service account
SA_NAME="wikijs-runner"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

echo "⚙ Wiki.js — Cloud Run Deployment"
echo "==================================="
echo "Project:  ${PROJECT_ID}"
echo "Region:   ${REGION}"
echo "Service:  ${SERVICE_NAME}"
echo "SQL:      ${SQL_INSTANCE_NAME}"
echo "SA:       ${SA_EMAIL}"
echo ""

if [ "${PROJECT_ID}" = "your-project-id" ]; then
    echo "ERROR: Set GOOGLE_CLOUD_PROJECT before running this script."
    exit 1
fi

# Get Cloud SQL connection name
SQL_CONNECTION_NAME=$(gcloud sql instances describe "${SQL_INSTANCE_NAME}" \
    --project="${PROJECT_ID}" \
    --format="value(connectionName)" 2>/dev/null)

if [ -z "${SQL_CONNECTION_NAME}" ]; then
    echo "ERROR: Cloud SQL instance '${SQL_INSTANCE_NAME}' not found."
    echo "  Run provision-wikijs.sh first."
    exit 1
fi
echo "SQL connection: ${SQL_CONNECTION_NAME}"
echo ""

# ---------------------------------------------------------------------------
# Step 1: Build the container image
# ---------------------------------------------------------------------------
echo "📦 Building Wiki.js container image..."

gcloud builds submit \
    --project="${PROJECT_ID}" \
    --config=cloud_install/cloudbuild-wikijs.yaml \
    --substitutions="_REGION=${REGION}" \
    .

# ---------------------------------------------------------------------------
# Step 2: Deploy to Cloud Run
# ---------------------------------------------------------------------------
echo ""
echo "🚀 Deploying Wiki.js to Cloud Run..."

gcloud run deploy "${SERVICE_NAME}" \
    --project="${PROJECT_ID}" \
    --region="${REGION}" \
    --image="${IMAGE_NAME}:latest" \
    --platform=managed \
    --port=3000 \
    --memory=512Mi \
    --cpu=1 \
    --min-instances=0 \
    --max-instances=3 \
    --timeout=300 \
    --concurrency=80 \
    --service-account="${SA_EMAIL}" \
    --add-cloudsql-instances="${SQL_CONNECTION_NAME}" \
    --set-env-vars="DB_TYPE=postgres" \
    --set-env-vars="DB_HOST=/cloudsql/${SQL_CONNECTION_NAME}" \
    --set-env-vars="DB_PORT=5432" \
    --set-env-vars="DB_NAME=${SQL_DB_NAME}" \
    --set-env-vars="DB_SSL=false" \
    --set-secrets="DB_USER=${SECRET_DB_USERNAME}:latest,DB_PASS=${SECRET_DB_PASSWORD}:latest" \
    --allow-unauthenticated

# ---------------------------------------------------------------------------
# Step 3: Display URL
# ---------------------------------------------------------------------------
echo ""
echo "=============================================="
SERVICE_URL=$(gcloud run services describe "${SERVICE_NAME}" \
    --project="${PROJECT_ID}" \
    --region="${REGION}" \
    --format="value(status.url)" 2>/dev/null)

echo "✓ Wiki.js deployed!"
echo ""
echo "URL:     ${SERVICE_URL}"
echo "Service: ${SERVICE_NAME}"
echo "Region:  ${REGION}"
echo ""
echo "First visit will show the Wiki.js setup wizard."
echo "Create your admin account and configure the wiki."
echo ""
