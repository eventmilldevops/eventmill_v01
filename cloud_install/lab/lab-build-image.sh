#!/bin/bash
# =============================================================================
# Event Mill — training lab, build the shared lab image
# =============================================================================
#
# Builds ONE image from this checkout with Cloud Build and pushes it as
#   <region>-docker.pkg.dev/<project>/eventmill/event-mill-lab:<tag>
#   <region>-docker.pkg.dev/<project>/eventmill/event-mill-lab:latest
# then records <tag> in ~/.eventmill/lab-image.env. lab-deploy.sh deploys
# exactly that tag to every lab service, so all students run identical code,
# and rebuilding the primary event-mill service changes nothing in the lab.
#
# Deploys nothing and touches no secret. The only permissions it needs are the
# ones any image build needs.
#
# The tag is the git short SHA of HEAD, and reaches the runtime as
# EVENTMILL_BUILD_SHA. Uncommitted changes in the paths the image copies
# (framework/, plugins/, pyproject.toml, README.md) refuse the build, because
# the tag would then name a commit the image does not match. ALLOW_DIRTY=1
# builds anyway, tagged <sha>-dirty-<UTC stamp>.
#
# If an image with a clean SHA tag already exists, the build is skipped and
# that tag is recorded. FORCE=1 rebuilds anyway.
#
# The build steps mirror Step 6 of deploy-cloudrun-secrets.sh: same Dockerfile,
# same context (the repo root, whatever the CWD). Change one and you must
# change the other.
#
# Usage:
#   bash cloud_install/lab/lab-build-image.sh
#   FORCE=1 bash cloud_install/lab/lab-build-image.sh
#   ALLOW_DIRTY=1 bash cloud_install/lab/lab-build-image.sh
#
# Caller needs: roles/cloudbuild.builds.editor, roles/serviceusage.serviceUsageConsumer,
# and roles/iam.serviceAccountUser on the build SA (see AGENTS.md).
# =============================================================================

set -uo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${LAB_DIR}/../.." && pwd)"

# shellcheck source=lab-common.sh
. "${LAB_DIR}/lab-common.sh"

lab_require_project
lab_require_region

FORCE="${FORCE:-0}"

if [ ! -f "${REPO_ROOT}/cloud_install/Dockerfile.cloudrun" ]; then
    echo "ERROR: cannot locate the repo root (derived ${REPO_ROOT})."
    exit 1
fi

# ---------------------------------------------------------------------------
# Tag
# ---------------------------------------------------------------------------
# Only the paths Dockerfile.cloudrun COPYs decide whether the image matches
# the commit. Uncommitted docs or cloud_install/ edits do not reach the image.
IMAGE_PATHS=(framework plugins pyproject.toml README.md)
SHA="$(git -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || true)"
STAMP="$(date -u +%Y%m%d-%H%M%S)"
DIRTY=0
if [ -z "${SHA}" ]; then
    TAG="nogit-${STAMP}"
    DIRTY=1
elif [ -n "$(git -C "${REPO_ROOT}" status --porcelain -- "${IMAGE_PATHS[@]}" 2>/dev/null)" ]; then
    # Refused by default. The runtime keeps only the first 12 characters of
    # EVENTMILL_BUILD_SHA, so "<sha>-dirty-..." is recorded as "<sha>-dirt",
    # which a reader can easily take for the commit itself.
    if [ "${ALLOW_DIRTY:-0}" != "1" ]; then
        echo "ERROR: uncommitted changes in paths that go into the image:"
        git -C "${REPO_ROOT}" status --short -- "${IMAGE_PATHS[@]}" | head -10 | sed 's/^/     /'
        echo ""
        echo "  Commit them so the lab runs a named commit, or build anyway with"
        echo "  ALLOW_DIRTY=1 (runtime records then show '${SHA}-dirt')."
        exit 1
    fi
    TAG="${SHA}-dirty-${STAMP}"
    DIRTY=1
else
    TAG="${SHA}"
fi

echo ""
echo "📦 Event Mill lab image"
echo "========================================================="
echo "Project:  ${PROJECT_ID}"
echo "Region:   ${REGION}"
echo "Image:    ${LAB_IMAGE_BASE}:${TAG}"
echo "Source:   ${REPO_ROOT}"
if [ "${DIRTY}" = "1" ] && [ -n "${SHA}" ]; then
    echo ""
    echo "⚠  ALLOW_DIRTY=1: building uncommitted changes in the image paths."
fi
echo ""

# ---------------------------------------------------------------------------
# Preflight: the Artifact Registry repo, in THIS region. Its path embeds the
# region, so a mismatch fails only at push time, after the whole build.
# ---------------------------------------------------------------------------
echo "🔎 Checking Artifact Registry..."
if ! err=$(gcloud artifacts repositories describe "${AR_REPO}" \
              --project="${PROJECT_ID}" --location="${REGION}" 2>&1 >/dev/null); then
    lab_report_error "Repository ${AR_REPO} in ${REGION}" "${err}"
    echo ""
    echo "   It is created by provision-gcp-project.sh. Check CLOUD_RUN_REGION."
    exit 1
fi
echo "   ✓ ${AR_REPO} (${REGION})"

# ---------------------------------------------------------------------------
# Reuse a clean image that already exists
# ---------------------------------------------------------------------------
record_tag() {
    mkdir -p "$(dirname "${LAB_IMAGE_ENV}")"
    printf 'LAB_IMAGE_TAG=%s\n' "$1" > "${LAB_IMAGE_ENV}"
    echo ""
    echo "✓ Lab image: ${LAB_IMAGE_BASE}:$1"
    echo "  Recorded in ${LAB_IMAGE_ENV}"
    echo "  Next: bash cloud_install/lab/lab-provision-secrets.sh  (if not done)"
    echo "        bash cloud_install/lab/lab-deploy.sh"
}

if [ "${DIRTY}" = "0" ] && [ "${FORCE}" != "1" ] \
   && gcloud artifacts docker images describe "${LAB_IMAGE_BASE}:${TAG}" \
          --project="${PROJECT_ID}" >/dev/null 2>&1; then
    echo "   ✓ ${LAB_IMAGE_BASE}:${TAG} already exists — not rebuilding (FORCE=1 to rebuild)"
    record_tag "${TAG}"
    exit 0
fi

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
echo ""
echo "🔨 Building with Cloud Build (several minutes)..."

BUILD_CONFIG="$(mktemp "${TMPDIR:-/tmp}/cloudbuild-eventmill-lab.XXXXXX.yaml")"
trap 'rm -f "${BUILD_CONFIG}"' EXIT

cat > "${BUILD_CONFIG}" <<BUILDEOF
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args:
      - 'build'
      - '-t'
      - '${LAB_IMAGE_BASE}:${TAG}'
      - '-t'
      - '${LAB_IMAGE_BASE}:latest'
      - '-f'
      - 'cloud_install/Dockerfile.cloudrun'
      - '.'
images:
  - '${LAB_IMAGE_BASE}:${TAG}'
  - '${LAB_IMAGE_BASE}:latest'
timeout: 2400s
options:
  logging: CLOUD_LOGGING_ONLY
BUILDEOF

if ! gcloud builds submit \
        --project="${PROJECT_ID}" \
        --config="${BUILD_CONFIG}" \
        "${REPO_ROOT}"; then
    echo ""
    echo "ERROR: Build failed. ${LAB_IMAGE_ENV} was not changed, so lab-deploy.sh"
    echo "       still points at the previous lab image, if there was one."
    exit 1
fi

record_tag "${TAG}"
