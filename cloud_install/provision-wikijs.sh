#!/bin/bash
# =============================================================================
# Wiki.js — GCP Infrastructure Provisioning
# =============================================================================
#
# Provisions Cloud SQL (PostgreSQL), service account, secrets, and IAM
# for running Wiki.js on Cloud Run alongside Event Mill.
#
# Prerequisites:
#   - gcloud CLI installed and authenticated
#   - GOOGLE_CLOUD_PROJECT set
#   - provision-gcp-project.sh already run (Artifact Registry exists)
#
# Usage:
#   export GOOGLE_CLOUD_PROJECT="your-project-id"
#   bash cloud_install/provision-wikijs.sh
#
# After provisioning:
#   bash cloud_install/deploy-wikijs.sh
# =============================================================================

set -e

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-your-project-id}"
REGION="${CLOUD_RUN_REGION:-northamerica-northeast2}"

# Cloud SQL instance
SQL_INSTANCE_NAME="${WIKIJS_SQL_INSTANCE:-wikijs-db}"
SQL_TIER="${WIKIJS_SQL_TIER:-db-f1-micro}"
SQL_DB_NAME="wikijs"
SQL_USER="wikijs"

# Service account
SA_NAME="wikijs-runner"
SA_DISPLAY_NAME="Wiki.js Cloud Run Service Account"

# Secrets
SECRET_DB_USERNAME="wikijs-db-user"
SECRET_DB_PASSWORD="wikijs-db-password"

echo "⚙ Wiki.js — GCP Infrastructure Provisioning"
echo "=============================================="
echo ""
echo "Project:        ${PROJECT_ID}"
echo "Region:         ${REGION}"
echo "SQL Instance:   ${SQL_INSTANCE_NAME} (${SQL_TIER})"
echo "Database:       ${SQL_DB_NAME}"
echo "SA:             ${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
echo ""

if [ "${PROJECT_ID}" = "your-project-id" ]; then
    echo "ERROR: Set GOOGLE_CLOUD_PROJECT before running this script."
    exit 1
fi

PROJECT_NUMBER=$(gcloud projects describe "${PROJECT_ID}" --format="value(projectNumber)")

# =============================================================================
# Section 1: Enable APIs
# =============================================================================

echo "📡 Section 1: Enabling APIs..."
echo ""

gcloud services enable sqladmin.googleapis.com --project="${PROJECT_ID}" --quiet
echo "   ✓ Cloud SQL Admin API"

gcloud services enable run.googleapis.com --project="${PROJECT_ID}" --quiet
echo "   ✓ Cloud Run API"

gcloud services enable secretmanager.googleapis.com --project="${PROJECT_ID}" --quiet
echo "   ✓ Secret Manager API"

gcloud services enable artifactregistry.googleapis.com --project="${PROJECT_ID}" --quiet
echo "   ✓ Artifact Registry API"

gcloud services enable cloudbuild.googleapis.com --project="${PROJECT_ID}" --quiet
echo "   ✓ Cloud Build API"

echo ""

# =============================================================================
# Section 2: Service Account
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
        --description="Service account for Wiki.js Cloud Run deployment" \
        --quiet
    echo "   ✓ Created service account: ${SA_EMAIL}"
fi
echo ""

# =============================================================================
# Section 3: Cloud SQL PostgreSQL Instance
# =============================================================================

echo "🗄 Section 3: Creating Cloud SQL instance..."
echo ""

if gcloud sql instances describe "${SQL_INSTANCE_NAME}" --project="${PROJECT_ID}" > /dev/null 2>&1; then
    echo "   ✓ Cloud SQL instance already exists: ${SQL_INSTANCE_NAME}"
else
    echo "   Creating Cloud SQL PostgreSQL instance (this takes 5-10 minutes)..."
    gcloud sql instances create "${SQL_INSTANCE_NAME}" \
        --project="${PROJECT_ID}" \
        --region="${REGION}" \
        --database-version=POSTGRES_15 \
        --tier="${SQL_TIER}" \
        --storage-size=10GB \
        --storage-auto-increase \
        --availability-type=zonal \
        --backup-start-time=03:00 \
        --quiet
    echo "   ✓ Created Cloud SQL instance: ${SQL_INSTANCE_NAME}"
fi

# Get the connection name (project:region:instance)
SQL_CONNECTION_NAME=$(gcloud sql instances describe "${SQL_INSTANCE_NAME}" \
    --project="${PROJECT_ID}" \
    --format="value(connectionName)")
echo "   Connection name: ${SQL_CONNECTION_NAME}"
echo ""

# =============================================================================
# Section 4: Database and User
# =============================================================================

echo "🗃 Section 4: Creating database and user..."
echo ""

# Prompt for DB credentials
read -r -p "   Enter database username [${SQL_USER}]: " INPUT_USER
SQL_USER="${INPUT_USER:-${SQL_USER}}"

read -r -s -p "   Enter database password: " DB_PASSWORD
echo ""
if [ -z "${DB_PASSWORD}" ]; then
    echo "   ERROR: Password cannot be empty."
    exit 1
fi
read -r -s -p "   Confirm database password: " DB_PASSWORD_CONFIRM
echo ""
if [ "${DB_PASSWORD}" != "${DB_PASSWORD_CONFIRM}" ]; then
    echo "   ERROR: Passwords do not match."
    exit 1
fi

# Create the database
if gcloud sql databases describe "${SQL_DB_NAME}" --instance="${SQL_INSTANCE_NAME}" --project="${PROJECT_ID}" > /dev/null 2>&1; then
    echo "   ✓ Database already exists: ${SQL_DB_NAME}"
else
    gcloud sql databases create "${SQL_DB_NAME}" \
        --instance="${SQL_INSTANCE_NAME}" \
        --project="${PROJECT_ID}" \
        --quiet
    echo "   ✓ Created database: ${SQL_DB_NAME}"
fi

# Create/update the user
if gcloud sql users list --instance="${SQL_INSTANCE_NAME}" --project="${PROJECT_ID}" --format="value(name)" | grep -q "^${SQL_USER}$"; then
    echo "   ✓ User already exists: ${SQL_USER} (password will be updated)"
    gcloud sql users set-password "${SQL_USER}" \
        --instance="${SQL_INSTANCE_NAME}" \
        --project="${PROJECT_ID}" \
        --password="${DB_PASSWORD}" \
        --quiet
else
    gcloud sql users create "${SQL_USER}" \
        --instance="${SQL_INSTANCE_NAME}" \
        --project="${PROJECT_ID}" \
        --password="${DB_PASSWORD}" \
        --quiet
    echo "   ✓ Created user: ${SQL_USER}"
fi
echo ""

# =============================================================================
# Section 5: Secrets
# =============================================================================

echo "🔐 Section 5: Storing secrets..."
echo ""

# Store DB username in Secret Manager
if gcloud secrets describe "${SECRET_DB_USERNAME}" --project="${PROJECT_ID}" > /dev/null 2>&1; then
    echo "   Username secret exists, adding new version..."
else
    gcloud secrets create "${SECRET_DB_USERNAME}" \
        --project="${PROJECT_ID}" \
        --replication-policy=automatic \
        --quiet
    echo "   ✓ Created secret: ${SECRET_DB_USERNAME}"
fi

echo -n "${SQL_USER}" | gcloud secrets versions add "${SECRET_DB_USERNAME}" \
    --project="${PROJECT_ID}" \
    --data-file=- \
    --quiet
echo "   ✓ Stored DB username in ${SECRET_DB_USERNAME}"

# Store DB password in Secret Manager
if gcloud secrets describe "${SECRET_DB_PASSWORD}" --project="${PROJECT_ID}" > /dev/null 2>&1; then
    echo "   Secret exists, adding new version..."
else
    gcloud secrets create "${SECRET_DB_PASSWORD}" \
        --project="${PROJECT_ID}" \
        --replication-policy=automatic \
        --quiet
    echo "   ✓ Created secret: ${SECRET_DB_PASSWORD}"
fi

echo -n "${DB_PASSWORD}" | gcloud secrets versions add "${SECRET_DB_PASSWORD}" \
    --project="${PROJECT_ID}" \
    --data-file=- \
    --quiet
echo "   ✓ Stored DB password in ${SECRET_DB_PASSWORD}"
echo ""

# =============================================================================
# Section 6: IAM Bindings
# =============================================================================

echo "🔑 Section 6: Configuring IAM..."
echo ""

# Grant Wiki.js SA access to Cloud SQL
echo "   Granting Cloud SQL Client role..."
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/cloudsql.client" \
    --quiet > /dev/null 2>&1 || \
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/cloudsql.client" \
    --condition='expression=true,title=wikijs-cloudsql,description=Wiki.js Cloud SQL access' \
    --quiet > /dev/null 2>&1
echo "   ✓ roles/cloudsql.client"

# Grant SA access to the DB username secret
gcloud secrets add-iam-policy-binding "${SECRET_DB_USERNAME}" \
    --project="${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/secretmanager.secretAccessor" \
    --quiet > /dev/null 2>&1
echo "   ✓ Secret accessor for ${SECRET_DB_USERNAME}"

# Grant SA access to the DB password secret
gcloud secrets add-iam-policy-binding "${SECRET_DB_PASSWORD}" \
    --project="${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/secretmanager.secretAccessor" \
    --quiet > /dev/null 2>&1
echo "   ✓ Secret accessor for ${SECRET_DB_PASSWORD}"

# Grant Logs Writer
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/logging.logWriter" \
    --quiet > /dev/null 2>&1 || \
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/logging.logWriter" \
    --condition='expression=true,title=wikijs-logging,description=Wiki.js logging access' \
    --quiet > /dev/null 2>&1
echo "   ✓ roles/logging.logWriter"

# Grant Cloud Build default SA permission to act as Wiki.js SA
DEFAULT_COMPUTE_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
gcloud iam service-accounts add-iam-policy-binding "${SA_EMAIL}" \
    --project="${PROJECT_ID}" \
    --member="serviceAccount:${DEFAULT_COMPUTE_SA}" \
    --role="roles/iam.serviceAccountUser" \
    --quiet > /dev/null 2>&1
echo "   ✓ Cloud Build can act as ${SA_NAME}"

echo ""

# =============================================================================
# Summary
# =============================================================================

echo "=============================================="
echo "✓ Wiki.js infrastructure provisioned!"
echo ""
echo "Cloud SQL instance:  ${SQL_INSTANCE_NAME}"
echo "Connection name:     ${SQL_CONNECTION_NAME}"
echo "Database:            ${SQL_DB_NAME}"
echo "User:                ${SQL_USER}"
echo "Username secret:     ${SECRET_DB_USERNAME}"
echo "Password secret:     ${SECRET_DB_PASSWORD}"
echo "Service account:     ${SA_EMAIL}"
echo ""
echo "Next steps:"
echo "  1. Deploy Wiki.js to Cloud Run:"
echo "     bash cloud_install/deploy-wikijs.sh"
echo ""
