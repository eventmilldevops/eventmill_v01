#!/bin/bash
# =============================================================================
# Event Mill v0.1.0 — Secret Manager Value Provisioning
# =============================================================================
#
# Interactively sets the real values for secrets created by
# provision-gcp-project.sh. Run this after provisioning, or any
# time you need to rotate a secret value.
#
# This script prompts for each value so nothing sensitive appears
# in shell history or script files.
#
# Prerequisites:
#   - provision-gcp-project.sh has been run (secrets exist)
#   - gcloud CLI authenticated with Secret Manager access
#
# Usage:
#   export GOOGLE_CLOUD_PROJECT="your-project-id"
#   bash cloud_install/provision-secrets.sh
#
# To update a single secret later without this script:
#   echo -n "new-value" | gcloud secrets versions add SECRET_NAME --data-file=-
# =============================================================================

set -e

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-your-project-id}"

echo "🔐 Event Mill v0.1.0 — Secret Value Provisioning"
echo "=================================================="
echo "Project: ${PROJECT_ID}"
echo ""

if [ "${PROJECT_ID}" = "your-project-id" ]; then
    echo "ERROR: Set GOOGLE_CLOUD_PROJECT before running this script."
    exit 1
fi

# ---------------------------------------------------------------------------
# Helper function
# ---------------------------------------------------------------------------

add_secret_version() {
    local secret_name=$1
    local description=$2
    local is_file=$3  # "file" if the value should be read from a file path

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Secret: ${secret_name}"
    echo "        ${description}"
    echo ""

    # Check if secret exists
    if ! gcloud secrets describe "${secret_name}" --project="${PROJECT_ID}" > /dev/null 2>&1; then
        echo "   WARNING: Secret '${secret_name}' does not exist."
        echo "   Run provision-gcp-project.sh first."
        echo ""
        return
    fi

    # Show current version count
    local version_count
    version_count=$(gcloud secrets versions list "${secret_name}" \
        --project="${PROJECT_ID}" \
        --format="value(name)" 2>/dev/null | wc -l)
    echo "   Current versions: ${version_count}"

    read -r -p "   Update this secret? [y/N]: " confirm
    if [[ ! "${confirm}" =~ ^[Yy]$ ]]; then
        echo "   Skipped."
        echo ""
        return
    fi

    if [ "${is_file}" = "file" ]; then
        # Read value from a file path
        read -r -p "   Enter file path: " file_path
        if [ ! -f "${file_path}" ]; then
            echo "   ERROR: File not found: ${file_path}"
            echo ""
            return
        fi
        gcloud secrets versions add "${secret_name}" \
            --project="${PROJECT_ID}" \
            --data-file="${file_path}" \
            --quiet
    else
        # Read value interactively (hidden input)
        read -r -s -p "   Enter value: " secret_value
        echo ""
        if [ -z "${secret_value}" ]; then
            echo "   ERROR: Empty value. Skipping."
            echo ""
            return
        fi
        echo -n "${secret_value}" | gcloud secrets versions add "${secret_name}" \
            --project="${PROJECT_ID}" \
            --data-file=- \
            --quiet
    fi

    echo "   ✓ Secret '${secret_name}' updated."
    echo ""
}

# =============================================================================
# Section 1: Gemini API Keys (dual-tier, restricted)
# =============================================================================
# Event Mill uses two separate API keys to isolate quota between model tiers.
# This prevents high-volume Flash calls (log scanning, pattern discovery)
# from consuming Pro quota (threat modeling, attack path reasoning).
#
# Keys are created via gcloud and restricted to generativelanguage.googleapis.com
# only. Display names match the OS environment variable names for traceability.
#
# Prerequisites:
#   - apikeys.googleapis.com enabled (provision-gcp-project.sh handles this)
#   - generativelanguage.googleapis.com enabled
# =============================================================================

create_restricted_gemini_key() {
    local display_name=$1   # matches the env var name for traceability
    local secret_name=$2    # Secret Manager entry to store the key string
    local description=$3    # human-readable purpose

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "API Key:  ${display_name}"
    echo "Secret:   ${secret_name}"
    echo "Purpose:  ${description}"
    echo ""

    # Check if a key with this display name already exists
    local existing_key
    existing_key=$(gcloud services api-keys list \
        --project="${PROJECT_ID}" \
        --filter="displayName='${display_name}'" \
        --format="value(uid)" 2>/dev/null | head -n1)

    if [ -n "${existing_key}" ]; then
        echo "   ✓ API key '${display_name}' already exists (uid: ${existing_key})"
        read -r -p "   Recreate and rotate this key? [y/N]: " confirm
        if [[ ! "${confirm}" =~ ^[Yy]$ ]]; then
            echo "   Skipped."
            echo ""
            return
        fi
        # Delete the old key before creating a new one
        echo "   Deleting old key..."
        gcloud services api-keys delete "${existing_key}" \
            --project="${PROJECT_ID}" \
            --quiet 2>/dev/null || true
    fi

    # Create a new API key restricted to Generative Language API only
    echo "   Creating restricted API key '${display_name}'..."
    local create_output
    create_output=$(gcloud services api-keys create \
        --project="${PROJECT_ID}" \
        --display-name="${display_name}" \
        --api-target=service=generativelanguage.googleapis.com \
        --quiet 2>&1)

    if [ -z "${create_output}" ]; then
        echo "   ERROR: Failed to create API key. Check permissions."
        echo ""
        return
    fi

    # Extract uid and keyString directly from the create response JSON
    # (--format flags don't apply cleanly to the async operation wrapper)
    local key_uid
    key_uid=$(echo "${create_output}" | grep -o '"uid":"[^"]*"' | head -1 | cut -d'"' -f4)
    local key_string
    key_string=$(echo "${create_output}" | grep -o '"keyString":"[^"]*"' | head -1 | cut -d'"' -f4)

    if [ -z "${key_string}" ]; then
        echo "   ERROR: Failed to extract key string from create output."
        echo "   Raw output:"
        echo "${create_output}"
        echo ""
        return
    fi

    echo "   ✓ API key created (uid: ${key_uid})"

    # Store the key string in Secret Manager
    if ! gcloud secrets describe "${secret_name}" --project="${PROJECT_ID}" > /dev/null 2>&1; then
        echo "   WARNING: Secret '${secret_name}' does not exist."
        echo "   Run provision-gcp-project.sh first."
        echo ""
        return
    fi

    echo -n "${key_string}" | gcloud secrets versions add "${secret_name}" \
        --project="${PROJECT_ID}" \
        --data-file=- \
        --quiet

    echo "   ✓ Key string stored in secret '${secret_name}'"
    echo ""
}

# GEMINI_FLASH_API_KEY — light tier
# Used by plugins with model_tier: "light" (log scanning, pattern discovery, ingestion)
create_restricted_gemini_key \
    "GEMINI_FLASH_API_KEY" \
    "eventmill-gemini-flash-api" \
    "Light tier — log scanning, pattern discovery, bulk operations"

# GEMINI_PRO_API_KEY — heavy tier
# Used by plugins with model_tier: "heavy" (threat modeling, attack paths, risk assessment)
create_restricted_gemini_key \
    "GEMINI_PRO_API_KEY" \
    "eventmill-gemini-pro-api" \
    "Heavy tier — threat modeling, attack path reasoning, risk assessment"

# =============================================================================
# Section 2: GCS Service Account Key
# =============================================================================
# JSON key file for a service account with Storage Object Viewer/User
# permissions on the log artifact bucket.
#
# NOTE: If your Cloud Run service uses workload identity or the default
# compute service account already has GCS access, you can skip this.
#
# To create a key:
#   gcloud iam service-accounts keys create /tmp/sa-key.json \
#       --iam-account=eventmill-runner@PROJECT_ID.iam.gserviceaccount.com
# =============================================================================

add_secret_version \
    "eventmill-gcs-sa" \
    "GCS service account key JSON file (skip if using workload identity)" \
    "file"

# =============================================================================
# Section 3: ttyd Web Terminal Credentials
# =============================================================================
# Basic auth credentials for the ttyd web terminal frontend.
# These protect the browser-based Event Mill shell from unauthorized access.
#
# Choose a strong password — this is the front door to your analysis platform.
# =============================================================================

add_secret_version \
    "eventmill-ttyd-user" \
    "ttyd web terminal username (e.g., analyst)"

add_secret_version \
    "eventmill-ttyd-cred" \
    "ttyd web terminal password (choose a strong password)"

# =============================================================================
# Done
# =============================================================================

echo "=================================================="
echo "✅ Secret provisioning complete."
echo ""
echo "To verify secrets have valid values:"
echo "  gcloud secrets versions list eventmill-gemini-flash-api --project=${PROJECT_ID}"
echo "  gcloud secrets versions list eventmill-gemini-pro-api   --project=${PROJECT_ID}"
echo "  gcloud secrets versions list eventmill-ttyd-user        --project=${PROJECT_ID}"
echo ""
echo "To deploy Event Mill:"
echo "  bash cloud_install/deploy-cloudrun-secrets.sh"
echo ""
