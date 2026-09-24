#!/bin/bash
# =============================================================================
# Event Mill — training lab, deploy event-mill-FIRST..LAST (default 2..19)
# =============================================================================
#
# Runs cloud_install/deploy-cloudrun-secrets.sh once per instance, changing
# only the service name and the ttyd secret pair. Everything else is shared:
# the image, the LLM key secrets, the buckets and the runtime service account.
#
# Per service:
#   CLOUD_RUN_SERVICE              event-mill-N
#   EVENTMILL_SECRET_TTYD_USER     eventmill-ttyd-user-N
#   EVENTMILL_SECRET_TTYD_CRED     eventmill-ttyd-cred-N
# Every service:
#   EVENTMILL_IMAGE_NAME=event-mill-lab                the shared lab image,
#   EVENTMILL_IMAGE_TAG=<LAB_IMAGE_TAG>, SKIP_BUILD=1  pinned, never rebuilt
#   CLOUD_RUN_MAX_INSTANCES=2                          two students per login
#   EVENTMILL_MOUNT_DAYBREAK=0                         Daybreak key not mounted
#
# Two students share each service and login. The deploy script's concurrency
# of 5 lets both land on one container, and ttyd gives each connection its own
# shell process. The second instance is headroom for when one container gets
# busy, not a seat per student. 18 services x 2 instances x 2 vCPU = 72 vCPU
# at full scale-out.
#
# Prerequisites:
#   1. bash cloud_install/lab/lab-build-image.sh   (builds and pins the image)
#   2. bash cloud_install/lab/lab-provision-secrets.sh
#
# Each deploy's full output goes to its own log. A failed instance does not
# stop the run; the summary lists which ones need a retry, e.g.:
#   FIRST=17 LAST=17 bash cloud_install/lab/lab-deploy.sh
#
# The deploy script's interactive prompts read from /dev/null here, so any
# "Deploy anyway?" condition aborts that instance instead of hanging the run.
#
# Usage:
#   bash cloud_install/lab/lab-deploy.sh                  # N = 2..19, one at a time
#   PARALLEL=4 bash cloud_install/lab/lab-deploy.sh       # four at a time
#   LAB_MIN_INSTANCES=1 bash cloud_install/lab/lab-deploy.sh   # no cold starts (billed while idle)
# =============================================================================

set -uo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_SCRIPT="${LAB_DIR}/../deploy-cloudrun-secrets.sh"

# shellcheck source=lab-common.sh
. "${LAB_DIR}/lab-common.sh"

lab_require_project
lab_require_region
lab_require_range

PARALLEL="${PARALLEL:-1}"
LAB_MIN_INSTANCES="${LAB_MIN_INSTANCES:-0}"
LAB_MAX_INSTANCES="${LAB_MAX_INSTANCES:-2}"
LAB_LLM_PROVIDERS="${LAB_LLM_PROVIDERS:-gcp_gemini anthropic openai}"

if ! [[ "${PARALLEL}" =~ ^[1-9][0-9]*$ ]]; then
    echo "ERROR: PARALLEL must be a positive integer (got '${PARALLEL}')."
    exit 1
fi

RUN_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_DIR="${HOME}/.eventmill/lab-logs/${RUN_STAMP}"
ROSTER="${HOME}/.eventmill/lab-roster.csv"
mkdir -p "${LOG_DIR}"

if [ -z "${LAB_IMAGE_TAG}" ] || [ "${LAB_IMAGE_TAG}" = "latest" ]; then
    echo "ERROR: no pinned lab image. Build one first:"
    echo "         bash cloud_install/lab/lab-build-image.sh"
    echo "       It records the tag in ${LAB_IMAGE_ENV}."
    exit 1
fi
IMAGE="${LAB_IMAGE_BASE}:${LAB_IMAGE_TAG}"

echo ""
echo "🧪 Event Mill lab deploy"
echo "========================================================="
echo "Project:     ${PROJECT_ID}"
echo "Region:      ${REGION}"
echo "Instances:   $(lab_service "${FIRST}") .. $(lab_service "${LAST}")  ($((LAST - FIRST + 1)) services)"
echo "Image:       ${IMAGE}"
echo "Scaling:     min ${LAB_MIN_INSTANCES}, max ${LAB_MAX_INSTANCES} per service"
echo "Peak vCPU:   $(( (LAST - FIRST + 1) * LAB_MAX_INSTANCES * 2 )) (2 per instance)"
echo "Providers:   ${LAB_LLM_PROVIDERS}  (Daybreak not mounted)"
echo "Parallel:    ${PARALLEL}"
echo "Logs:        ${LOG_DIR}"
echo ""

# ---------------------------------------------------------------------------
# Preflight: the pinned image. The lab never builds, so a missing image would
# fail all services one by one.
# ---------------------------------------------------------------------------
echo "🔎 Checking the shared image..."
if ! err=$(gcloud artifacts docker images describe "${IMAGE}" \
              --project="${PROJECT_ID}" 2>&1 >/dev/null); then
    lab_report_error "Image ${IMAGE}" "${err}"
    echo ""
    echo "   Rebuild it:  bash cloud_install/lab/lab-build-image.sh"
    exit 1
fi
echo "   ✓ ${IMAGE}"

# ---------------------------------------------------------------------------
# Preflight: every per-instance secret exists. The deploy script checks its
# own pair too; checking all of them here fails in seconds, not after N-1
# successful deploys.
# ---------------------------------------------------------------------------
echo "🔎 Checking per-instance ttyd secrets..."
MISSING=0
for ((n = FIRST; n <= LAST; n++)); do
    for secret in "$(lab_secret_user "${n}")" "$(lab_secret_cred "${n}")"; do
        if ! gcloud secrets describe "${secret}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
            echo "   ✗ ${secret} not found"
            MISSING=$((MISSING + 1))
        fi
    done
done
if [ "${MISSING}" -gt 0 ]; then
    echo ""
    echo "   ${MISSING} secret(s) missing. Run first:"
    echo "     FIRST=${FIRST} LAST=${LAST} bash cloud_install/lab/lab-provision-secrets.sh"
    exit 1
fi
echo "   ✓ $(( (LAST - FIRST + 1) * 2 )) secrets present"
echo ""

# ---------------------------------------------------------------------------
# Deploy
# ---------------------------------------------------------------------------
# EVENTMILL_DEPLOY_ENV points at a path that does not exist, so the deploy
# script does not re-source deploy.env. lab-common.sh already exported it;
# sourcing it again would overwrite the per-instance values set below.
deploy_one() {
    local n="$1" service log
    service="$(lab_service "${n}")"
    log="${LOG_DIR}/${service}.log"

    if EVENTMILL_DEPLOY_ENV="/nonexistent/lab-already-loaded" \
       CLOUD_RUN_SERVICE="${service}" \
       EVENTMILL_IMAGE_NAME="${LAB_IMAGE_NAME}" \
       EVENTMILL_IMAGE_TAG="${LAB_IMAGE_TAG}" \
       SKIP_BUILD=1 \
       EVENTMILL_SECRET_TTYD_USER="$(lab_secret_user "${n}")" \
       EVENTMILL_SECRET_TTYD_CRED="$(lab_secret_cred "${n}")" \
       EVENTMILL_MOUNT_DAYBREAK=0 \
       EVENTMILL_LLM_PROVIDERS="${LAB_LLM_PROVIDERS}" \
       CLOUD_RUN_MIN_INSTANCES="${LAB_MIN_INSTANCES}" \
       CLOUD_RUN_MAX_INSTANCES="${LAB_MAX_INSTANCES}" \
       bash "${DEPLOY_SCRIPT}" </dev/null >"${log}" 2>&1; then
        echo "ok" > "${LOG_DIR}/${service}.status"
        echo "   ✓ ${service}"
    else
        echo "fail" > "${LOG_DIR}/${service}.status"
        echo "   ✗ ${service} — see ${log}"
    fi
}

echo "🚀 Deploying..."
running=0
for ((n = FIRST; n <= LAST; n++)); do
    if [ "${PARALLEL}" -eq 1 ]; then
        deploy_one "${n}"
    else
        deploy_one "${n}" &
        running=$((running + 1))
        if [ "${running}" -ge "${PARALLEL}" ]; then
            wait -n
            running=$((running - 1))
        fi
    fi
done
wait

# ---------------------------------------------------------------------------
# Summary for this run, then the roster.
# ---------------------------------------------------------------------------
echo ""
OK=0
FAILED_LIST=()
for ((n = FIRST; n <= LAST; n++)); do
    service="$(lab_service "${n}")"
    status="$(cat "${LOG_DIR}/${service}.status" 2>/dev/null || echo "fail")"
    if [ "${status}" = "ok" ]; then
        OK=$((OK + 1))
    else
        FAILED_LIST+=("${n}")
    fi
done

# The roster is rebuilt from what Cloud Run is actually serving, across every
# lab service, not just this run's range, so retrying one instance does not
# shrink it. It holds service, URL and login, never the password, and lives
# under ~/.eventmill, outside the repo.
echo "========================================================="
echo "📋 Roster (all live lab services)"
echo "========================================================="
echo "service,url,login" > "${ROSTER}"
LIVE=$(gcloud run services list \
          --project="${PROJECT_ID}" --region="${REGION}" \
          --format="csv[no-heading](metadata.name,status.url)" 2>/dev/null)
while IFS=, read -r n service url; do
    printf '   %-16s %-22s %s\n' "${service}" "$(lab_user "${n}")" "${url}"
    echo "${service},${url},$(lab_user "${n}")" >> "${ROSTER}"
done < <(
    while IFS=, read -r service url; do
        n="${service#"${LAB_SERVICE_PREFIX}"}"
        [[ "${n}" =~ ^[0-9]+$ ]] && echo "${n},${service},${url}"
    done <<< "${LIVE}" | sort -t, -k1,1n
)

echo ""
echo "   This run: ${OK} of $((LAST - FIRST + 1)) deployed. Roster: ${ROSTER}"
if [ "${#FAILED_LIST[@]}" -gt 0 ]; then
    echo ""
    echo "   ✗ Failed: ${FAILED_LIST[*]}"
    echo "     Read ${LOG_DIR}/<service>.log, then retry one with e.g."
    echo "       FIRST=${FAILED_LIST[0]} LAST=${FAILED_LIST[0]} bash cloud_install/lab/lab-deploy.sh"
    exit 1
fi
echo ""
echo "   Next: bash cloud_install/lab/lab-verify.sh"
