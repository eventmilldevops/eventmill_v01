#!/bin/bash
# Event Mill v0.1.0 - Deploy Server Bootstrap
# Run once on the dedicated Linux deploy server to set up prerequisites.
#
# What this does:
#   1. Installs/updates Google Cloud SDK (if not present)
#   2. Installs Docker (if not present)
#   3. Clones the Event Mill repo (or pulls latest)
#   4. Creates the config directory for secrets/env
#
# Usage:
#   bash setup-deploy-server.sh

set -e

REPO_URL="https://github.com/eventmilldevops/eventmill_v01.git"
INSTALL_DIR="${EVENTMILL_INSTALL_DIR:-${HOME}/eventmill_v01}"
CONFIG_DIR="${HOME}/.eventmill"

echo "⚙ Event Mill v0.1.0 — Deploy Server Setup"
echo "============================================"
echo "Repo:       ${REPO_URL}"
echo "Install to: ${INSTALL_DIR}"
echo "Config:     ${CONFIG_DIR}"
echo ""

# ---------------------------------------------------------------------------
# Step 1: Check for Google Cloud SDK
# ---------------------------------------------------------------------------
if command -v gcloud &>/dev/null; then
    echo "✓ Google Cloud SDK found: $(gcloud --version 2>/dev/null | head -1)"
else
    echo "⚠ Google Cloud SDK not found."
    echo "  Install it from: https://cloud.google.com/sdk/docs/install"
    echo "  Or run:"
    echo "    curl https://sdk.cloud.google.com | bash"
    echo "    exec -l \$SHELL"
    echo ""
    echo "  Re-run this script after installing gcloud."
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 2: Check for Docker
# ---------------------------------------------------------------------------
if command -v docker &>/dev/null; then
    echo "✓ Docker found: $(docker --version)"
else
    echo "ℹ Docker not found (optional — only needed for local image testing)."
fi

# ---------------------------------------------------------------------------
# Step 3: Clone or pull the repo
# ---------------------------------------------------------------------------
echo ""
if [ -d "${INSTALL_DIR}/.git" ]; then
    echo "📥 Pulling latest from GitHub..."
    cd "${INSTALL_DIR}"
    git pull --ff-only
else
    echo "📥 Cloning repo..."
    git clone "${REPO_URL}" "${INSTALL_DIR}"
    cd "${INSTALL_DIR}"
fi

echo "✓ Repo at: ${INSTALL_DIR}"
echo "  Branch: $(git branch --show-current)"
echo "  Commit: $(git log -1 --format='%h %s')"

# ---------------------------------------------------------------------------
# Step 4: Create config directory
# ---------------------------------------------------------------------------
echo ""
mkdir -p "${CONFIG_DIR}"

if [ ! -f "${CONFIG_DIR}/deploy.env" ]; then
    cat > "${CONFIG_DIR}/deploy.env" <<'ENVEOF'
# Event Mill deploy configuration
#
# provision-gcp-project.sh and deploy-cloudrun-secrets.sh load this file
# automatically. Sourcing it by hand is only needed for gcloud builds submit,
# which cannot read it:
#   source ~/.eventmill/deploy.env
#
# GOOGLE_CLOUD_PROJECT, CLOUD_RUN_REGION and EVENTMILL_BUCKET_PREFIX are the
# three that matter. Anything already exported in your shell wins over this.

# Required: GCP project ID
export GOOGLE_CLOUD_PROJECT="your-project-id"

# Required: Bucket prefix — must match the value used when running provision-gcp-project.sh
# Buckets created will be: {prefix}-log-analysis, {prefix}-threat-modeling,
#                          {prefix}-network-forensics, {prefix}-common
# Default convention: {project_id}-eventmill (set after GOOGLE_CLOUD_PROJECT is known)
export EVENTMILL_BUCKET_PREFIX="${GOOGLE_CLOUD_PROJECT}-eventmill"

# Required: region. MUST match the region you provision in — the Artifact
# Registry image path embeds it, so a mismatch fails the deploy preflight.
# Deliberately left blank: a pre-filled region is how deploys end up pointed
# at a region nothing was provisioned in.
export CLOUD_RUN_REGION=""

# Legacy single-bucket override (backward compatibility only — leave empty for new deployments)
export GCS_LOG_BUCKET=""

# Secret names in GCP Secret Manager
# Dual Gemini keys — display names match the env vars for traceability.
# Anthropic and OpenAI take one key each: neither vendor splits keys by tier.
# All four are mounted on every deployment, the unadopted ones holding the
# literal "placeholder", so the revision shape is identical everywhere and
# adopting a vendor is a secret version plus a restart rather than a redeploy.
export EVENTMILL_SECRET_GEMINI_FLASH="eventmill-gemini-flash-api"
export EVENTMILL_SECRET_GEMINI_PRO="eventmill-gemini-pro-api"
export EVENTMILL_SECRET_ANTHROPIC="eventmill-anthropic-api"
export EVENTMILL_SECRET_OPENAI="eventmill-openai-api"
export EVENTMILL_SECRET_GCS_SA="eventmill-gcs-sa"
export EVENTMILL_SECRET_TTYD_USER="eventmill-ttyd-user"
export EVENTMILL_SECRET_TTYD_CRED="eventmill-ttyd-cred"

# Providers this deployment may bind, space-separated. All three by default.
# Known ids: gcp_gemini anthropic openai — an unknown one is refused, not
# ignored, because a typo would otherwise deploy with that provider silently
# absent.
#
# Leave this alone. A provider whose key is absent or still holds the seeded
# "placeholder" is skipped at runtime and reported as dormant, so naming all
# three costs nothing; removing one means a vendor with a real key in Secret
# Manager never binds, and the symptom is a vendor that is simply missing
# rather than an error. Adopting a vendor is a secret version plus a restart.
# A key can be verified before adoption with 'providers probe <id>'.
export EVENTMILL_LLM_PROVIDERS="gcp_gemini anthropic openai openai_daybreak_red openai_daybreak_blue"

# ttyd web terminal credentials (used by deploy-cloudrun.sh quick deploy only)
export TTYD_USERNAME="analyst"
export TTYD_PASSWORD="changeme"

# Log level for the deployed service
export EVENTMILL_LOG_LEVEL="INFO"

# Native-document latency model for threat_intel_ingester's page-range
# batching (seconds). Leave unset to use the values compiled into the plugin.
# These decide how a large PDF is split, NOT how long a run may take, and the
# shipped model overestimates a 154-page report by ~6x — which over-splits it
# into many small calls and separates pages that should be read together.
# Retune here rather than rebuilding the image, then confirm against the
# "[PLAN] ... est. Ns" line the next run logs.
#   export EVENTMILL_NATIVE_BASE_S="10"
#   export EVENTMILL_NATIVE_S_PER_PAGE="0.3"
#   export EVENTMILL_NATIVE_S_PER_CANDIDATE="0.7"
ENVEOF
    echo "✓ Created ${CONFIG_DIR}/deploy.env"
    echo "  Edit this file with your project settings before deploying."
else
    echo "✓ Config exists: ${CONFIG_DIR}/deploy.env"
fi

# ---------------------------------------------------------------------------
# Step 5: Make deploy scripts executable
# ---------------------------------------------------------------------------
chmod +x "${INSTALL_DIR}/cloud_install/"*.sh 2>/dev/null || true

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo "============================================"
echo "✅ Deploy server setup complete."
echo ""
echo "Next steps:"
echo "  1. Edit config:    nano ~/.eventmill/deploy.env"
echo "     GOOGLE_CLOUD_PROJECT and CLOUD_RUN_REGION are required and blank."
echo "  2. Authenticate:   gcloud auth login"
echo "  3. Set project:    gcloud config set project YOUR_PROJECT_ID"
echo "  4. Deploy:"
echo "     source ~/.eventmill/deploy.env"
echo "     cd ${INSTALL_DIR}"
echo "     bash cloud_install/deploy-cloudrun-secrets.sh"
echo ""
echo "To update later:"
echo "     cd ${INSTALL_DIR} && git pull && bash cloud_install/deploy-cloudrun-secrets.sh"
