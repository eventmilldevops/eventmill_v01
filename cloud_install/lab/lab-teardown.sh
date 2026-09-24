#!/bin/bash
# =============================================================================
# Event Mill — training lab, teardown
# =============================================================================
#
# Deletes services event-mill-FIRST..LAST and their per-instance ttyd secrets.
#
# Never touches the primary event-mill service, the shared LLM key secrets,
# the shared eventmill-ttyd-user/cred pair, the image, or the buckets. Every
# name it deletes is built from lab_service / lab_secret_* with an integer N,
# so none of those can be matched.
#
# Artifacts students wrote to the shared buckets are NOT removed. Clean those
# separately if the lab data should not persist. The event-mill-lab image is
# kept too, so the same build can be redeployed for the next session.
#
# Usage:
#   bash cloud_install/lab/lab-teardown.sh           # asks for confirmation
#   bash cloud_install/lab/lab-teardown.sh --yes
#   KEEP_SECRETS=1 bash cloud_install/lab/lab-teardown.sh   # services only
# =============================================================================

set -uo pipefail

# shellcheck source=lab-common.sh
. "$(dirname "${BASH_SOURCE[0]}")/lab-common.sh"

lab_require_project
lab_require_region
lab_require_range

KEEP_SECRETS="${KEEP_SECRETS:-0}"
ASSUME_YES=0
[ "${1:-}" = "--yes" ] && ASSUME_YES=1

echo ""
echo "🧹 Lab teardown — ${PROJECT_ID} / ${REGION}"
echo "   Services: $(lab_service "${FIRST}") .. $(lab_service "${LAST}")"
if [ "${KEEP_SECRETS}" = "1" ]; then
    echo "   Secrets:  kept (KEEP_SECRETS=1)"
else
    echo "   Secrets:  $(lab_secret_user "${FIRST}") .. $(lab_secret_cred "${LAST}")"
fi
echo ""

if [ "${ASSUME_YES}" != "1" ]; then
    read -r -p "   Delete these? This cannot be undone. [y/N]: " confirm
    [[ "${confirm}" =~ ^[Yy]$ ]] || { echo "   Aborted."; exit 1; }
    echo ""
fi

FAILED=0
for ((n = FIRST; n <= LAST; n++)); do
    service="$(lab_service "${n}")"
    if gcloud run services describe "${service}" \
            --project="${PROJECT_ID}" --region="${REGION}" >/dev/null 2>&1; then
        if err=$(gcloud run services delete "${service}" \
                    --project="${PROJECT_ID}" --region="${REGION}" \
                    --quiet 2>&1 >/dev/null); then
            echo "   ✓ deleted service ${service}"
        else
            lab_report_error "service ${service}" "${err}"
            FAILED=$((FAILED + 1))
        fi
    else
        echo "   · ${service} not present"
    fi

    [ "${KEEP_SECRETS}" = "1" ] && continue

    for secret in "$(lab_secret_user "${n}")" "$(lab_secret_cred "${n}")"; do
        if gcloud secrets describe "${secret}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
            if err=$(gcloud secrets delete "${secret}" \
                        --project="${PROJECT_ID}" --quiet 2>&1 >/dev/null); then
                echo "   ✓ deleted secret ${secret}"
            else
                lab_report_error "secret ${secret}" "${err}"
                FAILED=$((FAILED + 1))
            fi
        else
            echo "   · ${secret} not present"
        fi
    done
done

echo ""
if [ "${FAILED}" -gt 0 ]; then
    echo "✗ ${FAILED} deletion(s) failed; see above. Re-running is safe."
    exit 1
fi
echo "✓ Teardown complete."
