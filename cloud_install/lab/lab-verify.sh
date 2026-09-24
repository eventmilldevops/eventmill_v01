#!/bin/bash
# =============================================================================
# Event Mill — training lab, verify each instance's login
# =============================================================================
#
# For each N in FIRST..LAST, requests the service URL twice:
#   without credentials          -> expect 401
#   as yegN.bsides / its password -> expect 200
#
# The second check is the one that matters. It proves the instance mounted its
# OWN secret pair rather than the shared eventmill-ttyd-user/cred, and that
# the password survived the container's `sh -c` expansion intact.
#
# Credentials go to curl through a config on stdin, never argv.
#
# The first request to a service scaled to zero includes a cold start, so the
# timeout is generous.
#
# Usage:
#   bash cloud_install/lab/lab-verify.sh
#   FIRST=9 LAST=9 bash cloud_install/lab/lab-verify.sh
# =============================================================================

set -uo pipefail

# shellcheck source=lab-common.sh
. "$(dirname "${BASH_SOURCE[0]}")/lab-common.sh"

lab_require_project
lab_require_region
lab_require_range
lab_require_password_prefix

CURL_TIMEOUT="${CURL_TIMEOUT:-90}"

# curl config syntax: a double-quoted string, with \ and " escaped.
curl_quote() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    printf '"%s"' "${s}"
}

echo ""
echo "🔎 Verifying lab logins, instances ${FIRST}..${LAST}"
echo ""

FAILED=()
for ((n = FIRST; n <= LAST; n++)); do
    service="$(lab_service "${n}")"
    url=$(gcloud run services describe "${service}" \
            --project="${PROJECT_ID}" --region="${REGION}" \
            --format="value(status.url)" 2>/dev/null)
    if [ -z "${url}" ]; then
        printf '   ✗ %-16s not deployed\n' "${service}"
        FAILED+=("${n}")
        continue
    fi

    anon=$(curl -s -o /dev/null -w '%{http_code}' --max-time "${CURL_TIMEOUT}" "${url}/")
    authed=$(printf 'user = %s\n' "$(curl_quote "$(lab_user "${n}"):$(lab_password "${n}")")" \
               | curl -s -o /dev/null -w '%{http_code}' --max-time "${CURL_TIMEOUT}" \
                      -K - "${url}/")

    if [ "${anon}" = "401" ] && [ "${authed}" = "200" ]; then
        printf '   ✓ %-16s anon %s, login %s\n' "${service}" "${anon}" "${authed}"
    else
        printf '   ✗ %-16s anon %s (want 401), login %s (want 200)\n' \
               "${service}" "${anon}" "${authed}"
        FAILED+=("${n}")
    fi
done

echo ""
if [ "${#FAILED[@]}" -gt 0 ]; then
    echo "✗ Failed: ${FAILED[*]}"
    echo "  000 is a timeout or connection failure; re-run once to rule out a cold start."
    exit 1
fi
echo "✓ All $((LAST - FIRST + 1)) instances accept only their own login."
