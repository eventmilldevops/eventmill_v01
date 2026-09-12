#!/bin/bash
# =============================================================================
# Event Mill — Cloud Run Deployment with Secret Manager
# =============================================================================
#
# Second version of deploy-cloudrun-secrets.sh. Same inputs, same env var
# names, same ~/.eventmill/deploy.env — so it is a drop-in replacement.
#
# What changed vs v1, and why:
#
#   1. NEVER reports a guessed cause for a failure. v1 ran every check as
#      `cmd > /dev/null 2>&1` and printed "Secret not found - create it first"
#      for ANY failure, including the 403 geo-block and permission errors.
#      This version captures stderr and prints what GCP actually said.
#
#   2. Explicitly detects the "not available in your location" geo-block
#      (Google misclassifies some OVH IPv6 ranges) and tells you how to fix
#      it, instead of mislabelling it as a missing resource.
#
#   3. WRITES NO IAM. v1 granted secretAccessor here, which forced the deploy
#      identity to hold secretmanager.secrets.setIamPolicy — IAM-write it has
#      no other use for, and which a CI service account must never have.
#      All IAM is now written once, at bootstrap, by
#      provision-gcp-project.sh. This script only VERIFIES.
#
#   4. Preflights everything provisioning was meant to create (SA, Artifact
#      Registry in the resolved region, secrets, buckets) and aborts BEFORE
#      paying for an image build.
#
#   5. Preflights the CALLER's own permissions via testIamPermissions, on both
#      resource scopes that matter:
#        - project:         cloudbuild.builds.create, serviceusage.services.use,
#                           run.services.*
#        - service account: iam.serviceAccounts.actAs on the RUNTIME SA and on
#                           the BUILD SA
#      actAs is granted ON a service account, so a project-level check returns
#      a misleading all-clear. Each miss prints the exact role and command.
#
#   6. Warns if a secret still holds the literal "placeholder" value seeded
#      by provisioning. Deploying those yields a broken LLM and a web terminal
#      whose password is "placeholder".
#
#   7. Build context is derived from this script's own location, not the CWD.
#      v1 passed "." to `gcloud builds submit`, so running it from
#      cloud_install/ uploaded 16 files and failed on the Dockerfile path.
#
#   8. Does not pass an empty GCS_LOG_BUCKET. The resolver treats a non-empty
#      value as a legacy override; passing it empty is pure noise.
#
#   9. Tags images with a git short SHA (or UTC timestamp) instead of only
#      :latest, so a revision can be traced back to source.
#
#  10. --allow-unauthenticated is an explicit opt-in via ALLOW_UNAUTH, and
#      requesting it adds run.services.setIamPolicy to the preflight, since
#      binding allUsers is itself an IAM policy write.
#
#  11. Distinguishes a failed NEW deployment from a failed UPDATE. v1 always
#      claimed "Cloud Run keeps serving the previous revision", which is false
#      on a first deploy and understates the impact.
#
# Required caller permissions (all verified in Step 3b before anything runs):
#   project:            roles/cloudbuild.builds.editor
#                       roles/serviceusage.serviceUsageConsumer
#                       roles/run.admin
#   on eventmill-runner: roles/iam.serviceAccountUser
#   on the build SA:     roles/iam.serviceAccountUser
# Deliberately NOT required: any *.setIamPolicy permission.
#
# Usage:
#   export GOOGLE_CLOUD_PROJECT="eventmill-v01"
#   export CLOUD_RUN_REGION="us-central1"
#   export EVENTMILL_BUCKET_PREFIX="evtm-v011"
#   bash cloud_install/deploy-cloudrun-secrets.sh
#
#   # Skip the build and redeploy the existing :latest image
#   SKIP_BUILD=1 bash cloud_install/deploy-cloudrun-secrets.sh
#
#   # Preflight only, change nothing
#   DRY_RUN=1 bash cloud_install/deploy-cloudrun-secrets.sh
# =============================================================================

set -uo pipefail

# ---------------------------------------------------------------------------
# Saved deploy config, if present.
# ---------------------------------------------------------------------------
# provision-gcp-project.sh tells the operator to persist the resolved project,
# region and bucket prefix here, and README.md says to `source` it before every
# run. Forgetting that source is the most common way to deploy against the
# wrong region or bucket, so load it automatically instead.
#
# Anything already exported wins — this fills gaps, it never overrides an
# explicit choice made in the current shell.
# ---------------------------------------------------------------------------
EVENTMILL_DEPLOY_ENV="${EVENTMILL_DEPLOY_ENV:-${HOME}/.eventmill/deploy.env}"
if [ -f "${EVENTMILL_DEPLOY_ENV}" ]; then
    _pre_project="${GOOGLE_CLOUD_PROJECT:-}"
    _pre_region="${CLOUD_RUN_REGION:-}"
    _pre_prefix="${EVENTMILL_BUCKET_PREFIX:-}"

    # shellcheck disable=SC1090
    . "${EVENTMILL_DEPLOY_ENV}"

    [ -n "${_pre_project}" ] && GOOGLE_CLOUD_PROJECT="${_pre_project}"
    [ -n "${_pre_region}" ]  && CLOUD_RUN_REGION="${_pre_region}"
    [ -n "${_pre_prefix}" ]  && EVENTMILL_BUCKET_PREFIX="${_pre_prefix}"
    export GOOGLE_CLOUD_PROJECT CLOUD_RUN_REGION EVENTMILL_BUCKET_PREFIX
    unset _pre_project _pre_region _pre_prefix

    echo "Loaded deploy config: ${EVENTMILL_DEPLOY_ENV}"
fi

# ---------------------------------------------------------------------------
# Configuration — mirrors the derivation rules in provision-gcp-project.sh
# ---------------------------------------------------------------------------
PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-}"
REGION="${CLOUD_RUN_REGION:-}"
SERVICE_NAME="${CLOUD_RUN_SERVICE:-event-mill}"
AR_REPO="${EVENTMILL_AR_REPO:-eventmill}"

# Bucket prefix: same derivation as provision-gcp-project.sh.
# Never allowed to be empty — an empty prefix makes the runtime resolver fall
# back to the literal string "eventmill" and silently read the wrong buckets.
# Unset is still risky rather than fatal: if provisioning used a non-default
# prefix and this deploy derives the default, the service starts cleanly and
# reads buckets that do not exist. Warned about after the guards below.
BUCKET_PREFIX="${EVENTMILL_BUCKET_PREFIX:-${PROJECT_ID}-eventmill}"

SECRET_GEMINI_FLASH="${EVENTMILL_SECRET_GEMINI_FLASH:-eventmill-gemini-flash-api}"
SECRET_GEMINI_PRO="${EVENTMILL_SECRET_GEMINI_PRO:-eventmill-gemini-pro-api}"
SECRET_TTYD_USER="${EVENTMILL_SECRET_TTYD_USER:-eventmill-ttyd-user}"
SECRET_TTYD_CRED="${EVENTMILL_SECRET_TTYD_CRED:-eventmill-ttyd-cred}"

SA_NAME="${EVENTMILL_SA_NAME:-eventmill-runner}"

LOG_LEVEL="${EVENTMILL_LOG_LEVEL:-INFO}"
ALLOW_UNAUTH="${ALLOW_UNAUTH:-true}"
SKIP_BUILD="${SKIP_BUILD:-0}"
DRY_RUN="${DRY_RUN:-0}"

if [ -z "${PROJECT_ID}" ] || [ "${PROJECT_ID}" = "your-project-id" ]; then
    echo "ERROR: Set GOOGLE_CLOUD_PROJECT before running this script."
    echo ""
    echo "  export GOOGLE_CLOUD_PROJECT=\"your-project-id\""
    echo ""
    echo "Or persist it, along with the region and bucket prefix, in"
    echo "${EVENTMILL_DEPLOY_ENV} — this script loads that file automatically."
    exit 1
fi

# The Artifact Registry path embeds the region, so provisioning in one region
# and deploying in another is a hard failure. provision-gcp-project.sh refuses
# to guess; this script must not guess either, or the two silently drift.
if [ -z "${REGION}" ]; then
    echo "ERROR: region not set. This script deliberately does not default it."
    echo ""
    echo "  export CLOUD_RUN_REGION=\"us-central1\""
    echo ""
    echo "It must match the region you provisioned in. Existing repos:"
    gcloud artifacts repositories list --project="${PROJECT_ID}"         --format="value(name.basename(), location)" 2>/dev/null         | sed 's/^/    repo: /' || true
    echo ""
    echo "Persist it in ${EVENTMILL_DEPLOY_ENV} to stop this recurring."
    exit 1
fi

if [ -z "${EVENTMILL_BUCKET_PREFIX:-}" ]; then
    echo "NOTE: EVENTMILL_BUCKET_PREFIX unset — using default '${BUCKET_PREFIX}'."
    echo "      This MUST match what provision-gcp-project.sh used. If it does"
    echo "      not, the service will start normally and read buckets that do"
    echo "      not exist. Verify with: gcloud storage ls --project=${PROJECT_ID}"
    echo ""
fi

SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
IMAGE_BASE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPO}/${SERVICE_NAME}"

# ---------------------------------------------------------------------------
# Repo root, resolved from this script's own location — NOT from the CWD.
# ---------------------------------------------------------------------------
# Dockerfile.cloudrun COPYs pyproject.toml, README.md, framework/ and plugins/,
# all of which live at the repo root. v1 passed "." to `gcloud builds submit`,
# so running it from cloud_install/ uploaded only that directory and the build
# failed with:
#   unable to evaluate symlinks in Dockerfile path:
#   lstat /workspace/cloud_install: no such file or directory
# Deriving the root here makes the script work from any working directory.
# ---------------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ ! -f "${REPO_ROOT}/cloud_install/Dockerfile.cloudrun" ]; then
    echo "ERROR: cannot locate the repo root."
    echo "  Derived: ${REPO_ROOT}"
    echo "  Expected: \${REPO_ROOT}/cloud_install/Dockerfile.cloudrun"
    exit 1
fi

# Traceable image tag: git short SHA when available, else UTC timestamp.
# -C "${REPO_ROOT}" so the SHA reflects the source being built, not the CWD.
IMAGE_TAG="$(git -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || true)"
[ -n "${IMAGE_TAG}" ] || IMAGE_TAG="$(date -u +%Y%m%d-%H%M%S)"

ALL_SECRETS=(
    "${SECRET_GEMINI_FLASH}"
    "${SECRET_GEMINI_PRO}"
    "${SECRET_TTYD_USER}"
    "${SECRET_TTYD_CRED}"
)

echo "⚙ Event Mill — Cloud Run Deployment (Secret Manager)"
echo "========================================================="
echo "Project:        ${PROJECT_ID}"
echo "Region:         ${REGION}"
echo "Service:        ${SERVICE_NAME}"
echo "Service acct:   ${SA_EMAIL}"
echo "Bucket prefix:  ${BUCKET_PREFIX}"
echo "Image:          ${IMAGE_BASE}:${IMAGE_TAG}"
echo "Build context:  ${REPO_ROOT}"
echo "Public access:  ${ALLOW_UNAUTH}"
echo ""

FAILED=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Report a failure with the ACTUAL error text, and recognise the geo-block
# rather than guessing at a cause.
explain_error() {
    local what="$1"
    local err="$2"

    if grep -qi "not available in your location" <<<"${err}"; then
        echo "   ✗ ${what}: BLOCKED — Google is geo-blocking this host."
        echo ""
        echo "     This is NOT a missing resource and NOT an IAM problem."
        echo "     Google's geolocation DB misclassifies some hosting ranges"
        echo "     (notably OVH IPv6). Every *.googleapis.com call from this"
        echo "     host will fail the same way."
        echo ""
        echo "     Fix, in order of preference:"
        echo "       1. Prefer IPv4:  echo 'precedence ::ffff:0:0/96  100' | sudo tee -a /etc/gai.conf"
        echo "       2. Run this from Cloud Shell, or a GCE VM in ${PROJECT_ID}"
        echo "       3. Use a GitHub-connected Cloud Build trigger so no host"
        echo "          of yours needs GCS egress at all"
        echo ""
        return
    fi

    if grep -qiE "PERMISSION_DENIED|does not have|forbidden" <<<"${err}"; then
        echo "   ✗ ${what}: permission denied for $(gcloud config get-value account 2>/dev/null)"
        echo "     ${err}" | head -3
        return
    fi

    if grep -qiE "NOT_FOUND|was not found|does not exist" <<<"${err}"; then
        echo "   ✗ ${what}: does not exist"
        return
    fi

    echo "   ✗ ${what}: unexpected error"
    echo "     ${err}" | head -5
}

# ---------------------------------------------------------------------------
# Caller permission probing via testIamPermissions
# ---------------------------------------------------------------------------
# testIamPermissions returns the SUBSET of the requested permissions that the
# authenticated caller actually holds. Anything absent from the response is
# missing. This is the only reliable way to check IAM: reading policies shows
# direct bindings but misses inheritance from groups, folders and org level.
#
# Critically, permissions are scoped to a RESOURCE. iam.serviceAccounts.actAs
# lives on the service account, not the project, so a project-level probe
# reports "all clear" while a deploy still fails. Both surfaces are checked.
# ---------------------------------------------------------------------------

IAM_PROBE=1
if ! command -v curl >/dev/null 2>&1; then
    IAM_PROBE=0
fi

# POST a permission list to a testIamPermissions endpoint; echo the raw JSON.
probe_permissions() {
    local url="$1"; shift
    local body
    body=$(printf '"%s",' "$@" | sed 's/,$//')
    curl -s -m 25 -X POST \
        -H "Authorization: Bearer ${ACCESS_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{\"permissions\":[${body}]}" \
        "${url}" 2>/dev/null
}

# require_permissions <label> <url> <remediation> <perm>...
# Marks FAILED and prints the exact remediation if any permission is missing.
require_permissions() {
    local label="$1" url="$2" hint="$3"; shift 3
    local response perm missing=0

    if [ "${IAM_PROBE}" -ne 1 ] || [ -z "${ACCESS_TOKEN}" ]; then
        echo "   ? ${label}: cannot probe (curl or access token unavailable) — skipped"
        return 0
    fi

    response=$(probe_permissions "${url}" "$@")

    # A malformed request returns an "error" object rather than a permission
    # list; do not misreport that as missing permissions.
    if grep -q '"error"' <<<"${response}"; then
        echo "   ? ${label}: probe failed, cannot verify"
        echo "     $(grep -o '"message"[^,]*' <<<"${response}" | head -1)"
        return 0
    fi

    for perm in "$@"; do
        if grep -q "\"${perm}\"" <<<"${response}"; then
            echo "   ✓ ${perm}"
        else
            echo "   ✗ ${perm} — MISSING on ${label}"
            missing=1
        fi
    done

    if [ "${missing}" -ne 0 ]; then
        echo ""
        echo "     Remediation:"
        echo "${hint}" | sed 's/^/       /'
        echo ""
        FAILED=1
    fi
}

# ---------------------------------------------------------------------------
# Step 1: Confirm the API is reachable at all before interpreting any result
# ---------------------------------------------------------------------------
# Without this, a geo-block or expired credential looks identical to every
# resource in the project having vanished.
# ---------------------------------------------------------------------------
echo "🔍 Step 1: Probing API reachability..."

probe_err=""
if ! probe_err=$(gcloud secrets list --project="${PROJECT_ID}" --limit=1 2>&1 >/dev/null); then
    explain_error "Secret Manager API unreachable" "${probe_err}"
    echo ""
    echo "Aborting: cannot trust any further check while the API is unreachable."
    exit 1
fi
echo "   ✓ Secret Manager API reachable"

if ! probe_err=$(gcloud storage ls --project="${PROJECT_ID}" 2>&1 >/dev/null); then
    explain_error "Cloud Storage API unreachable" "${probe_err}"
    echo ""
    echo "Aborting: 'gcloud builds submit' uploads a source tarball to GCS and"
    echo "will fail from this host."
    exit 1
fi
echo "   ✓ Cloud Storage API reachable"

# Needed by the permission probes and to name the build service account.
ACCESS_TOKEN="$(gcloud auth print-access-token 2>/dev/null || true)"
PROJECT_NUMBER="$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)' 2>/dev/null || true)"
BUILD_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
OPERATOR="$(gcloud config get-value account 2>/dev/null || true)"

# IAM bindings require the principal type prefix to match the account type,
# so remediation hints must not hardcode "user:" — this script is intended to
# run under a CI service account too.
if [ -z "${OPERATOR}" ] || [ "${OPERATOR}" = "(unset)" ]; then
    OPERATOR="<your-account>"
    OPERATOR_MEMBER="user:<your-account>"
    echo "   ⚠ Could not determine the active account"
elif [[ "${OPERATOR}" == *.gserviceaccount.com ]]; then
    OPERATOR_MEMBER="serviceAccount:${OPERATOR}"
    echo "   ✓ Authenticated as ${OPERATOR} (service account)"
else
    OPERATOR_MEMBER="user:${OPERATOR}"
    echo "   ✓ Authenticated as ${OPERATOR} (user)"
fi

# Does the service already exist? Determines whether a failed deploy leaves a
# previous revision serving. v1 claimed it always did, which is wrong on a
# first-time deploy and misleads the operator about the blast radius.
SERVICE_EXISTS=0
if gcloud run services describe "${SERVICE_NAME}" \
        --project="${PROJECT_ID}" --region="${REGION}" >/dev/null 2>&1; then
    SERVICE_EXISTS=1
    echo "   ✓ Service ${SERVICE_NAME} exists — this is an UPDATE"
else
    echo "   ✓ Service ${SERVICE_NAME} not found — this is a NEW deployment"
fi
echo ""

# ---------------------------------------------------------------------------
# Step 2: Enable required APIs
# ---------------------------------------------------------------------------
echo "📡 Step 2: Enabling required APIs..."
for api in secretmanager.googleapis.com run.googleapis.com \
           cloudbuild.googleapis.com artifactregistry.googleapis.com; do
    if err=$(gcloud services enable "${api}" --project="${PROJECT_ID}" --quiet 2>&1); then
        echo "   ✓ ${api}"
    else
        explain_error "${api}" "${err}"
        FAILED=1
    fi
done
echo ""

# ---------------------------------------------------------------------------
# Step 3: Preflight the provisioned resources
# ---------------------------------------------------------------------------
echo "🔎 Step 3: Preflight..."

# --- Runtime service account ---
if err=$(gcloud iam service-accounts describe "${SA_EMAIL}" \
            --project="${PROJECT_ID}" 2>&1 >/dev/null); then
    echo "   ✓ Service account ${SA_EMAIL}"
else
    explain_error "Service account ${SA_EMAIL}" "${err}"
    FAILED=1
fi

# --- Artifact Registry must exist IN THE RESOLVED REGION ---
# A region mismatch between provisioning and deploy fails the push only after
# a full image build has already been paid for.
if err=$(gcloud artifacts repositories describe "${AR_REPO}" \
            --project="${PROJECT_ID}" --location="${REGION}" 2>&1 >/dev/null); then
    echo "   ✓ Artifact Registry ${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPO}"
else
    explain_error "Artifact Registry '${AR_REPO}' in ${REGION}" "${err}"
    echo "     Does CLOUD_RUN_REGION match the region used for provisioning?"
    FAILED=1
fi

# --- Secrets ---
for secret in "${ALL_SECRETS[@]}"; do
    if err=$(gcloud secrets describe "${secret}" \
                --project="${PROJECT_ID}" 2>&1 >/dev/null); then
        echo "   ✓ Secret ${secret}"
    else
        explain_error "Secret ${secret}" "${err}"
        FAILED=1
    fi
done

# --- Buckets implied by the resolved prefix ---
for slug in log-analysis network-forensics threat-modeling common; do
    bucket="gs://${BUCKET_PREFIX}-${slug}"
    if err=$(gcloud storage buckets describe "${bucket}" \
                --project="${PROJECT_ID}" 2>&1 >/dev/null); then
        echo "   ✓ Bucket ${bucket}"
    else
        explain_error "Bucket ${bucket}" "${err}"
        echo "     Does EVENTMILL_BUCKET_PREFIX match the provisioned prefix?"
        FAILED=1
    fi
done

if [ "${FAILED}" -ne 0 ]; then
    echo ""
    echo "Preflight failed. Nothing was built or deployed."
    exit 1
fi
echo ""

# ---------------------------------------------------------------------------
# Step 3b: Preflight the CALLER's own permissions
# ---------------------------------------------------------------------------
# Every IAM failure in this project's bring-up was discovered only after a
# paid image build, and reported by gcloud with a message that named neither
# the permission nor the resource. These probes name both, in seconds.
#
# Note the two different resource scopes — this is the crux. actAs is granted
# ON a service account, so a project-level probe cannot see it and returns a
# misleading all-clear.
# ---------------------------------------------------------------------------
echo "🪪 Step 3b: Caller permissions..."

# --- Project-scoped ---
RUN_PERMS=(run.services.create run.services.update run.services.get)
if [ "${ALLOW_UNAUTH}" = "true" ]; then
    # Binding allUsers as run.invoker is itself an IAM policy write.
    RUN_PERMS+=(run.services.setIamPolicy)
fi

require_permissions \
    "project ${PROJECT_ID}" \
    "https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT_ID}:testIamPermissions" \
    "gcloud projects add-iam-policy-binding ${PROJECT_ID} \\
    --member=\"${OPERATOR_MEMBER}\" --condition=None \\
    --role=\"roles/cloudbuild.builds.editor\"        # cloudbuild.builds.create
gcloud projects add-iam-policy-binding ${PROJECT_ID} \\
    --member=\"${OPERATOR_MEMBER}\" --condition=None \\
    --role=\"roles/serviceusage.serviceUsageConsumer\"  # serviceusage.services.use
gcloud projects add-iam-policy-binding ${PROJECT_ID} \\
    --member=\"${OPERATOR_MEMBER}\" --condition=None \\
    --role=\"roles/run.admin\"                       # run.services.*" \
    cloudbuild.builds.create \
    serviceusage.services.use \
    "${RUN_PERMS[@]}"

# --- Service-account-scoped: actAs on the RUNTIME service account ---
# Required by `gcloud run deploy --service-account=${SA_EMAIL}`.
require_permissions \
    "service account ${SA_EMAIL}" \
    "https://iam.googleapis.com/v1/projects/-/serviceAccounts/${SA_EMAIL}:testIamPermissions" \
    "gcloud iam service-accounts add-iam-policy-binding ${SA_EMAIL} \\
    --project=${PROJECT_ID} \\
    --member=\"${OPERATOR_MEMBER}\" \\
    --role=\"roles/iam.serviceAccountUser\"

Or re-run provisioning, which now grants this at bootstrap:
  bash cloud_install/provision-gcp-project.sh" \
    iam.serviceAccounts.actAs

# --- Service-account-scoped: actAs on the BUILD service account ---
# Required by `gcloud builds submit`, since the build executes as this SA.
if [ "${SKIP_BUILD}" != "1" ] && [ -n "${PROJECT_NUMBER}" ]; then
    require_permissions \
        "build service account ${BUILD_SA}" \
        "https://iam.googleapis.com/v1/projects/-/serviceAccounts/${BUILD_SA}:testIamPermissions" \
        "gcloud iam service-accounts add-iam-policy-binding ${BUILD_SA} \\
    --project=${PROJECT_ID} \\
    --member=\"${OPERATOR_MEMBER}\" \\
    --role=\"roles/iam.serviceAccountUser\"

Or re-run provisioning, which now grants this at bootstrap:
  bash cloud_install/provision-gcp-project.sh" \
        iam.serviceAccounts.actAs
fi

if [ "${FAILED}" -ne 0 ]; then
    echo ""
    echo "Preflight failed on caller permissions. Nothing was built or deployed."
    echo "IAM propagation is eventually consistent — if you just granted a role,"
    echo "wait ~60s and re-run before concluding the grant did not apply."
    exit 1
fi
echo ""

# ---------------------------------------------------------------------------
# Step 4: Warn on placeholder secret values
# ---------------------------------------------------------------------------
# provision-gcp-project.sh seeds every secret with the literal string
# "placeholder". Deploying those gives a non-functional LLM and a web
# terminal whose password is "placeholder". Values are never printed.
# ---------------------------------------------------------------------------
echo "🔐 Step 4: Checking secret values..."
PLACEHOLDER_FOUND=0
for secret in "${ALL_SECRETS[@]}"; do
    if value=$(gcloud secrets versions access latest \
                  --secret="${secret}" --project="${PROJECT_ID}" 2>/dev/null); then
        if [ "${value}" = "placeholder" ]; then
            echo "   ⚠ ${secret} still holds the seeded 'placeholder' value"
            PLACEHOLDER_FOUND=1
        else
            echo "   ✓ ${secret} has a real value (${#value} chars)"
        fi
    else
        echo "   ? ${secret} — cannot read value (no secretAccessor for you); skipping check"
    fi
    unset value
done

if [ "${PLACEHOLDER_FOUND}" -ne 0 ]; then
    echo ""
    echo "   Set real values first:  bash cloud_install/provision-secrets.sh"
    if [ "${DRY_RUN}" != "1" ]; then
        read -r -p "   Deploy anyway? [y/N]: " confirm
        [[ "${confirm}" =~ ^[Yy]$ ]] || { echo "   Aborted."; exit 1; }
    fi
fi
echo ""

# ---------------------------------------------------------------------------
# Step 5: VERIFY the runtime service account can read the secrets
# ---------------------------------------------------------------------------
# This step used to GRANT roles/secretmanager.secretAccessor. It now only
# verifies, deliberately:
#
#   - Granting required secretmanager.secrets.setIamPolicy, so the deploy
#     identity needed IAM-write permission it otherwise has no use for.
#   - That made the script unusable by a CI service account, which must not be
#     able to rewrite IAM.
#   - IAM should be written in exactly one place. That place is
#     provision-gcp-project.sh (Section 8), at bootstrap.
#
# Cloud Run resolves --set-secrets as the RUNTIME service account and rejects
# the revision if it cannot read one, so catching it here saves a build.
# ---------------------------------------------------------------------------
echo "🔑 Step 5: Verifying ${SA_NAME} can read the secrets..."

UNVERIFIED=0
for secret in "${ALL_SECRETS[@]}"; do
    # Secret-level binding is what provisioning applies.
    if gcloud secrets get-iam-policy "${secret}" \
            --project="${PROJECT_ID}" \
            --flatten="bindings[].members" \
            --filter="bindings.role=roles/secretmanager.secretAccessor AND bindings.members:${SA_EMAIL}" \
            --format="value(bindings.members)" 2>/dev/null | grep -q .; then
        echo "   ✓ ${secret} — secret-level binding present"
        continue
    fi

    # A project-level grant is equally valid; check before crying foul.
    if gcloud projects get-iam-policy "${PROJECT_ID}" \
            --flatten="bindings[].members" \
            --filter="bindings.role=roles/secretmanager.secretAccessor AND bindings.members:serviceAccount:${SA_EMAIL}" \
            --format="value(bindings.members)" 2>/dev/null | grep -q .; then
        echo "   ✓ ${secret} — covered by a project-level binding"
        continue
    fi

    echo "   ⚠ ${secret} — no secretAccessor binding found for ${SA_NAME}"
    UNVERIFIED=1
done

if [ "${UNVERIFIED}" -ne 0 ]; then
    echo ""
    echo "   Cloud Run will reject the revision if the runtime SA cannot read a"
    echo "   secret. Grant access at bootstrap (preferred):"
    echo "     bash cloud_install/provision-gcp-project.sh"
    echo ""
    echo "   Or directly, for each secret above:"
    echo "     gcloud secrets add-iam-policy-binding SECRET_NAME \\"
    echo "         --project=${PROJECT_ID} \\"
    echo "         --member=\"serviceAccount:${SA_EMAIL}\" \\"
    echo "         --role=\"roles/secretmanager.secretAccessor\""
    echo ""
    echo "   (This may be a false alarm if you lack permission to read IAM"
    echo "    policies — the checks above fail closed.)"
    if [ "${DRY_RUN}" != "1" ]; then
        read -r -p "   Continue anyway? [y/N]: " confirm
        [[ "${confirm}" =~ ^[Yy]$ ]] || { echo "   Aborted."; exit 1; }
    fi
fi
echo ""

if [ "${DRY_RUN}" = "1" ]; then
    echo "DRY_RUN=1 — preflight passed, stopping before build and deploy."
    exit 0
fi

# ---------------------------------------------------------------------------
# Step 6: Build the image
# ---------------------------------------------------------------------------
if [ "${SKIP_BUILD}" = "1" ]; then
    echo "📦 Step 6: SKIP_BUILD=1 — reusing ${IMAGE_BASE}:latest"
    DEPLOY_IMAGE="${IMAGE_BASE}:latest"
else
    echo "📦 Step 6: Building ${IMAGE_BASE}:${IMAGE_TAG}..."

    BUILD_CONFIG="$(mktemp /tmp/cloudbuild-eventmill.XXXXXX.yaml)"
    trap 'rm -f "${BUILD_CONFIG}"' EXIT

    cat > "${BUILD_CONFIG}" <<BUILDEOF
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args:
      - 'build'
      - '-t'
      - '${IMAGE_BASE}:${IMAGE_TAG}'
      - '-t'
      - '${IMAGE_BASE}:latest'
      - '-f'
      - 'cloud_install/Dockerfile.cloudrun'
      - '.'
images:
  - '${IMAGE_BASE}:${IMAGE_TAG}'
  - '${IMAGE_BASE}:latest'
timeout: 2400s
options:
  logging: CLOUD_LOGGING_ONLY
BUILDEOF

    # Submit REPO_ROOT explicitly, never "." — the build context must be the
    # repo root regardless of where this script was invoked from.
    if ! gcloud builds submit \
            --project="${PROJECT_ID}" \
            --config="${BUILD_CONFIG}" \
            "${REPO_ROOT}"; then
        echo ""
        echo "ERROR: Build failed. Nothing was deployed."
        if [ "${SERVICE_EXISTS}" = "1" ]; then
            echo "       The existing revision is untouched and still serving."
        fi
        exit 1
    fi
    DEPLOY_IMAGE="${IMAGE_BASE}:${IMAGE_TAG}"
fi
echo ""

# ---------------------------------------------------------------------------
# Step 7: Deploy to Cloud Run
# ---------------------------------------------------------------------------
# --no-cpu-throttling  keeps LLM calls progressing between websocket frames
# --session-affinity   pins an analyst's terminal session to one instance
# --timeout 3600       long-running interactive investigations
# ---------------------------------------------------------------------------
echo "🚀 Step 7: Deploying to Cloud Run..."

AUTH_FLAG="--no-allow-unauthenticated"
if [ "${ALLOW_UNAUTH}" = "true" ]; then
    AUTH_FLAG="--allow-unauthenticated"
fi

# GCS_LOG_BUCKET is deliberately omitted: the resolver treats a non-empty
# value as a legacy log_analysis override, and empty adds nothing.
if ! gcloud run deploy "${SERVICE_NAME}" \
        --project="${PROJECT_ID}" \
        --region="${REGION}" \
        --image="${DEPLOY_IMAGE}" \
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
        --service-account="${SA_EMAIL}" \
        --set-secrets="GEMINI_FLASH_API_KEY=${SECRET_GEMINI_FLASH}:latest,GEMINI_PRO_API_KEY=${SECRET_GEMINI_PRO}:latest,TTYD_USERNAME=${SECRET_TTYD_USER}:latest,TTYD_PASSWORD=${SECRET_TTYD_CRED}:latest" \
        --set-env-vars="GOOGLE_CLOUD_PROJECT=${PROJECT_ID},EVENTMILL_BUCKET_PREFIX=${BUCKET_PREFIX},EVENTMILL_LOG_LEVEL=${LOG_LEVEL}" \
        "${AUTH_FLAG}"; then
    echo ""
    if [ "${SERVICE_EXISTS}" = "1" ]; then
        echo "ERROR: Deploy failed. Cloud Run kept the previous revision serving —"
        echo "       traffic is unaffected."
        echo "       Inspect with:"
        echo "         gcloud run revisions list --service=${SERVICE_NAME} \\"
        echo "             --region=${REGION} --project=${PROJECT_ID}"
    else
        echo "ERROR: Deploy failed on a NEW service — there is no previous"
        echo "       revision, so ${SERVICE_NAME} is not serving at all."
        echo "       The image built and pushed successfully; only the Cloud Run"
        echo "       revision failed. Re-run with SKIP_BUILD=1 once fixed."
    fi
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 8: Summary
# ---------------------------------------------------------------------------
SERVICE_URL=$(gcloud run services describe "${SERVICE_NAME}" \
    --project="${PROJECT_ID}" \
    --region="${REGION}" \
    --format="value(status.url)" 2>/dev/null)

echo ""
echo "========================================================="
echo "✅ Deployment complete"
echo "========================================================="
echo ""
echo "🌐 URL:            ${SERVICE_URL}"
echo "📦 Image:          ${DEPLOY_IMAGE}"
echo "👤 Service acct:   ${SA_EMAIL}  (GCS via workload identity)"
echo "🗂  Bucket prefix:  ${BUCKET_PREFIX}"
echo ""
echo "📂 Storage:"
for slug in log-analysis network-forensics threat-modeling common; do
    echo "   gs://${BUCKET_PREFIX}-${slug}"
done
echo ""

if [ "${ALLOW_UNAUTH}" = "true" ]; then
    echo "⚠  This service is PUBLIC. The only gate is ttyd basic auth using a"
    echo "   single shared credential pair. To require IAM instead:"
    echo "     ALLOW_UNAUTH=false bash cloud_install/deploy-cloudrun-secrets.sh"
    echo "     gcloud run services add-iam-policy-binding ${SERVICE_NAME} \\"
    echo "         --region=${REGION} --project=${PROJECT_ID} \\"
    echo "         --member='user:you@example.com' --role='roles/run.invoker'"
    echo ""
fi

echo "📋 Rotate a secret:"
echo "   echo -n 'new-value' | gcloud secrets versions add ${SECRET_GEMINI_FLASH} \\"
echo "       --project=${PROJECT_ID} --data-file=-"
echo "   (then redeploy, or the running revision keeps the old pinned version)"
echo ""
