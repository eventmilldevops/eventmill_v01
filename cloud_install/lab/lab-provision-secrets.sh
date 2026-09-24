#!/bin/bash
# =============================================================================
# Event Mill — training lab, per-instance ttyd secrets
# =============================================================================
#
# For each N in FIRST..LAST, creates eventmill-ttyd-user-N and
# eventmill-ttyd-cred-N, sets their values, and grants the runtime service
# account secretAccessor on both.
#
# The grant lives here, not in the deploy, because deploy-cloudrun-secrets.sh
# deliberately writes no IAM. It only verifies, and Cloud Run rejects a
# revision whose runtime SA cannot read a mounted secret.
#
# Safe to re-run: an existing secret is kept, and a new version is added only
# when the stored value differs. The binding is idempotent.
#
# Values go to gcloud on stdin, never on the command line, so they do not show
# up in `ps` or shell history.
#
# Usage:
#   bash cloud_install/lab/lab-provision-secrets.sh             # N = 2..19
#   FIRST=5 LAST=5 bash cloud_install/lab/lab-provision-secrets.sh
#
# Caller needs: roles/secretmanager.admin (create, add versions, set IAM).
# =============================================================================

set -uo pipefail

# shellcheck source=lab-common.sh
. "$(dirname "${BASH_SOURCE[0]}")/lab-common.sh"

lab_require_project
lab_require_range
lab_require_password_prefix

echo ""
echo "🔐 Lab secrets — ${PROJECT_ID}, instances ${FIRST}..${LAST}"
echo "   Runtime SA: ${SA_EMAIL}"
echo ""

FAILED=0

# $1 = secret name, $2 = value
ensure_secret() {
    local secret="$1" value="$2" err current

    if gcloud secrets describe "${secret}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
        if current=$(gcloud secrets versions access latest \
                        --secret="${secret}" --project="${PROJECT_ID}" 2>/dev/null) \
           && [ "${current}" = "${value}" ]; then
            echo "   ✓ ${secret} — exists, value current"
        elif err=$(printf '%s' "${value}" | gcloud secrets versions add "${secret}" \
                      --project="${PROJECT_ID}" --data-file=- --quiet 2>&1 >/dev/null); then
            echo "   ✓ ${secret} — exists, new version added"
        else
            lab_report_error "${secret} — adding version failed" "${err}"
            return 1
        fi
    elif err=$(printf '%s' "${value}" | gcloud secrets create "${secret}" \
                  --project="${PROJECT_ID}" \
                  --data-file=- \
                  --labels="app=eventmill,purpose=lab" \
                  --quiet 2>&1 >/dev/null); then
        echo "   ✓ ${secret} — created"
    else
        lab_report_error "${secret} — create failed" "${err}"
        return 1
    fi

    if ! err=$(gcloud secrets add-iam-policy-binding "${secret}" \
                  --project="${PROJECT_ID}" \
                  --member="serviceAccount:${SA_EMAIL}" \
                  --role="roles/secretmanager.secretAccessor" \
                  --quiet 2>&1 >/dev/null); then
        lab_report_error "${secret} — secretAccessor binding failed" "${err}"
        return 1
    fi
    return 0
}

for ((n = FIRST; n <= LAST; n++)); do
    echo "── $(lab_service "${n}")  ($(lab_user "${n}"))"
    ensure_secret "$(lab_secret_user "${n}")" "$(lab_user "${n}")"     || FAILED=$((FAILED + 1))
    ensure_secret "$(lab_secret_cred "${n}")" "$(lab_password "${n}")" || FAILED=$((FAILED + 1))
done

echo ""
if [ "${FAILED}" -gt 0 ]; then
    echo "✗ ${FAILED} secret(s) failed. Fix the errors above and re-run;"
    echo "  secrets that succeeded are left as they are."
    exit 1
fi
echo "✓ All secrets for instances ${FIRST}..${LAST} are in place and readable by ${SA_NAME}."
echo "  Next: bash cloud_install/lab/lab-deploy.sh"
