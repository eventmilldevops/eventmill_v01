#!/bin/bash
# =============================================================================
# Event Mill — GCP Project Provisioning (v2)
# =============================================================================
#
# Second version of provision-gcp-project.sh. Same resources, same names, same
# environment variables — safe to run against an already-provisioned project.
#
# WHY THIS EXISTS
# ---------------
# v1 runs under `set -e` with most checks written as `cmd > /dev/null 2>&1`.
# Any unguarded failure aborts the script *silently* — no error, no banner.
# In practice that produced a half-provisioned project:
#
#   - Section 4 line 401 (`echo -n "" | gsutil cp - "${dest}"`) had no `|| true`
#     guard, so a single failed folder placeholder killed the run.
#   - Section 5 (Artifact Registry), Section 6 (secrets) and Section 7 (secret
#     IAM bindings) never executed, leaving the Artifact Registry repo absent
#     in the requested region and no secretAccessor bindings at all.
#
# WHAT CHANGED
# ------------
#   1. REGION MUST BE EXPLICIT. v1 silently defaulted to northamerica-northeast2.
#      Every region mismatch in this project traces back to that default, so v2
#      refuses to run without CLOUD_RUN_REGION (or --region) set.
#
#   2. NO SILENT ABORTS. Runs without `set -e`; every step reports success or
#      the ACTUAL error text, accumulates failures, and always reaches the
#      summary. Exit code is non-zero if anything failed.
#
#   3. Artifact Registry is created in the REQUESTED region, and the script
#      warns if a same-named repo exists in a DIFFERENT region (the exact
#      situation that produced "Repository 'eventmill' not found").
#
#   4. gsutil replaced with `gcloud storage` throughout. v1 mixed the two.
#
#   5. Secret IAM bindings are VERIFIED after being applied, not assumed.
#      v1 printed "✓ can read <secret>" unconditionally, even on failure.
#
#   6. Detects the "not available in your location" geo-block explicitly
#      instead of reporting it as a missing or name-collided resource.
#
# Usage:
#   export GOOGLE_CLOUD_PROJECT="eventmill-v01"
#   export CLOUD_RUN_REGION="us-central1"          # REQUIRED
#   export EVENTMILL_BUCKET_PREFIX="evtm-v011"     # must match existing buckets
#   bash cloud_install/provision-gcp-project-v2.sh
#
#   # Preflight only, change nothing:
#   DRY_RUN=1 bash cloud_install/provision-gcp-project-v2.sh
#
# Idempotent: existing buckets, secrets, repos and bindings are left alone.
# =============================================================================

set -uo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-}"
REGION="${CLOUD_RUN_REGION:-}"
BUCKET_PREFIX="${EVENTMILL_BUCKET_PREFIX:-}"

SA_NAME="eventmill-runner"
SA_DISPLAY_NAME="Event Mill Cloud Run Service Account"
AR_REPO="${EVENTMILL_AR_REPO:-eventmill}"
SERVICE_NAME="event-mill"
DRY_RUN="${DRY_RUN:-0}"

PILLAR_SLUGS=(log-analysis network-forensics threat-modeling)
COMMON_FOLDERS=(mitre capec cisa vendor_advisories threat_actors campaigns vulnerabilities)
SECRET_NAMES=(
    eventmill-gemini-flash-api
    eventmill-gemini-pro-api
    eventmill-gcs-sa
    eventmill-ttyd-user
    eventmill-ttyd-cred
)

FAILED=0
WARNED=0

# ---------------------------------------------------------------------------
# Argument parsing (env vars still work; flags win)
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --project)       PROJECT_ID="$2";     shift 2 ;;
        --region)        REGION="$2";         shift 2 ;;
        --bucket-prefix) BUCKET_PREFIX="$2";  shift 2 ;;
        --dry-run)       DRY_RUN=1;           shift   ;;
        *) echo "Unknown argument: $1"; exit 2 ;;
    esac
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Report the ACTUAL error, and name the geo-block rather than guessing.
explain_error() {
    local what="$1"
    local err="$2"

    if grep -qi "not available in your location" <<<"${err}"; then
        echo "   ✗ ${what}: BLOCKED — Google is geo-blocking this host."
        echo "     Not a missing resource, not an IAM problem, not a name collision."
        echo "     Google's geolocation DB misclassifies some hosting ranges"
        echo "     (notably OVH IPv6). Every *.googleapis.com call will fail here."
        echo "     Prefer IPv4:  echo 'precedence ::ffff:0:0/96  100' | sudo tee -a /etc/gai.conf"
        echo "     Or run this from Cloud Shell / a GCE VM in ${PROJECT_ID}."
        return
    fi
    if grep -qiE "PERMISSION_DENIED|does not have|caller does not have|forbidden" <<<"${err}"; then
        echo "   ✗ ${what}: permission denied"
        echo "     ${err}" | head -3
        return
    fi
    if grep -qiE "already own|already exists|ALREADY_EXISTS" <<<"${err}"; then
        echo "   ✗ ${what}: name already taken globally — override the prefix and re-run"
        return
    fi
    echo "   ✗ ${what}"
    echo "     ${err}" | head -5
}

# Add a project-level IAM binding; fall back to an always-true condition for
# organizations that require conditions on all project IAM bindings.
add_project_binding() {
    local member="$1" role="$2" err=""

    if err=$(gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
                --member="${member}" --role="${role}" --condition=None \
                --quiet 2>&1 >/dev/null); then
        echo "   ✓ ${role}"
        return 0
    fi
    if err=$(gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
                --member="${member}" --role="${role}" \
                --condition='expression=true,title=eventmill-bootstrap,description=Required for Event Mill bootstrap in condition-enforced IAM projects' \
                --quiet 2>&1 >/dev/null); then
        echo "   ✓ ${role} (with always-true condition)"
        return 0
    fi
    explain_error "${role} for ${member}" "${err}"
    WARNED=$((WARNED + 1))
    return 1
}

# ---------------------------------------------------------------------------
# Grant roles/iam.serviceAccountUser (which contains iam.serviceAccounts.actAs)
# on a service account RESOURCE.
#
# A service account is both an identity and a resource. actAs is what lets a
# principal ATTACH that identity to a workload (Cloud Run revision, Cloud Build
# build). It does NOT give the principal the service account's own permissions —
# that would be iam.serviceAccounts.getAccessToken.
#
# This is deliberately granted per-service-account rather than project-wide:
# a project-level grant would allow impersonating EVERY service account in the
# project, which defeats the purpose.
# ---------------------------------------------------------------------------
grant_actas() {
    local target_sa="$1" member="$2" label="$3" err=""

    if ! gcloud iam service-accounts describe "${target_sa}" \
            --project="${PROJECT_ID}" >/dev/null 2>&1; then
        echo "   ⊘ ${label}: target SA ${target_sa} does not exist — skipped"
        WARNED=$((WARNED + 1))
        return 1
    fi

    if err=$(gcloud iam service-accounts add-iam-policy-binding "${target_sa}" \
                --project="${PROJECT_ID}" \
                --member="${member}" \
                --role="roles/iam.serviceAccountUser" \
                --quiet 2>&1 >/dev/null); then
        echo "   ✓ ${label}"
        return 0
    fi

    explain_error "${label}" "${err}"
    echo "     Granting this needs iam.serviceAccounts.setIamPolicy on the target SA"
    echo "     (roles/iam.serviceAccountAdmin or roles/owner). Ask an admin to run:"
    echo "       gcloud iam service-accounts add-iam-policy-binding ${target_sa} \\"
    echo "           --project=${PROJECT_ID} \\"
    echo "           --member=\"${member}\" \\"
    echo "           --role=\"roles/iam.serviceAccountUser\""
    WARNED=$((WARNED + 1))
    return 1
}

# ---------------------------------------------------------------------------
# Section 0: Validate inputs — no silent defaults
# ---------------------------------------------------------------------------
echo "⚙ Event Mill — GCP Project Provisioning (v2)"
echo "============================================="
echo ""

if [ -z "${PROJECT_ID}" ] || [ "${PROJECT_ID}" = "your-project-id" ]; then
    echo "ERROR: project not set."
    echo "  export GOOGLE_CLOUD_PROJECT=\"your-project-id\"   (or --project)"
    exit 1
fi

# v1 defaulted REGION to northamerica-northeast2. That default is the root cause
# of the Artifact Registry / bucket / Cloud Run region mismatches in this
# project, so v2 will not guess.
if [ -z "${REGION}" ]; then
    echo "ERROR: region not set. v2 deliberately does not default it."
    echo ""
    echo "  export CLOUD_RUN_REGION=\"us-central1\"   (or --region us-central1)"
    echo ""
    echo "The Artifact Registry repo path embeds the region, so a mismatch"
    echo "between provisioning and deploy is a hard failure. Existing regions:"
    gcloud artifacts repositories list --project="${PROJECT_ID}" \
        --format="value(name.basename(), location)" 2>/dev/null \
        | sed 's/^/    repo: /' || true
    exit 1
fi

if [ -z "${BUCKET_PREFIX}" ]; then
    BUCKET_PREFIX="${PROJECT_ID}-eventmill"
    echo "NOTE: EVENTMILL_BUCKET_PREFIX unset — using default '${BUCKET_PREFIX}'."
    echo "      If your buckets use a different prefix, set it explicitly or the"
    echo "      deployed service will read the wrong (or empty) buckets."
    echo ""
fi

SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

echo "Project:        ${PROJECT_ID}"
echo "Region:         ${REGION}   (explicit)"
echo "Bucket prefix:  ${BUCKET_PREFIX}"
echo "Service acct:   ${SA_EMAIL}"
echo "Artifact repo:  ${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPO}"
echo "Cloud Run svc:  ${SERVICE_NAME}"
echo ""

# ---------------------------------------------------------------------------
# Section 1: Preflight — project access and API reachability
# ---------------------------------------------------------------------------
echo "🔍 Section 1: Preflight..."

if err=$(gcloud projects describe "${PROJECT_ID}" 2>&1 >/dev/null); then
    echo "   ✓ Project ${PROJECT_ID} accessible"
else
    explain_error "Project ${PROJECT_ID}" "${err}"
    echo ""
    echo "Aborting: cannot reach the project."
    exit 1
fi

# Probe Cloud Storage early. If this host is geo-blocked, every later check
# would report resources as "missing" — which is how v1 misled us repeatedly.
if err=$(gcloud storage ls --project="${PROJECT_ID}" 2>&1 >/dev/null); then
    echo "   ✓ Cloud Storage API reachable"
else
    explain_error "Cloud Storage API" "${err}"
    echo ""
    echo "Aborting: results would be unreliable while the API is unreachable."
    exit 1
fi

PROJECT_NUMBER=$(gcloud projects describe "${PROJECT_ID}" --format="value(projectNumber)" 2>/dev/null)
DEFAULT_COMPUTE_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
CLOUDBUILD_SA="${PROJECT_NUMBER}@cloudbuild.gserviceaccount.com"
echo "   ✓ Project number ${PROJECT_NUMBER}"

# Identify the operator running this script so Section 4 can grant them the
# actAs permissions the deploy step needs. Prefix must match the principal
# type or the IAM binding is rejected.
OPERATOR_ACCOUNT="${EVENTMILL_OPERATOR:-$(gcloud config get-value account 2>/dev/null)}"
if [ -z "${OPERATOR_ACCOUNT}" ] || [ "${OPERATOR_ACCOUNT}" = "(unset)" ]; then
    OPERATOR_MEMBER=""
    echo "   ⚠ Could not determine the active account — operator actAs grants will be skipped"
    WARNED=$((WARNED + 1))
elif [[ "${OPERATOR_ACCOUNT}" == *.gserviceaccount.com ]]; then
    OPERATOR_MEMBER="serviceAccount:${OPERATOR_ACCOUNT}"
    echo "   ✓ Operator ${OPERATOR_ACCOUNT} (service account)"
else
    OPERATOR_MEMBER="user:${OPERATOR_ACCOUNT}"
    echo "   ✓ Operator ${OPERATOR_ACCOUNT} (user)"
fi
echo ""

if [ "${DRY_RUN}" = "1" ]; then
    echo "DRY_RUN=1 — preflight passed, stopping before any changes."
    exit 0
fi

# ---------------------------------------------------------------------------
# Section 2: Enable APIs
# ---------------------------------------------------------------------------
echo "📡 Section 2: Enabling APIs..."

# compute.googleapis.com is included because `gcloud builds submit` runs builds
# as the Compute Engine default service account, which only exists once this
# API has been enabled. v1 omitted it, so its grants to DEFAULT_COMPUTE_SA
# could target a service account that did not exist.
for api in \
    run.googleapis.com \
    cloudbuild.googleapis.com \
    artifactregistry.googleapis.com \
    storage.googleapis.com \
    secretmanager.googleapis.com \
    generativelanguage.googleapis.com \
    logging.googleapis.com \
    apikeys.googleapis.com \
    iam.googleapis.com \
    compute.googleapis.com
do
    if err=$(gcloud services enable "${api}" --project="${PROJECT_ID}" --quiet 2>&1 >/dev/null); then
        echo "   ✓ ${api}"
    else
        explain_error "${api}" "${err}"
        FAILED=$((FAILED + 1))
    fi
done
echo ""

# ---------------------------------------------------------------------------
# Section 3: Service account
# ---------------------------------------------------------------------------
echo "👤 Section 3: Service account..."

if gcloud iam service-accounts describe "${SA_EMAIL}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    echo "   ✓ Already exists: ${SA_EMAIL}"
elif err=$(gcloud iam service-accounts create "${SA_NAME}" \
              --project="${PROJECT_ID}" \
              --display-name="${SA_DISPLAY_NAME}" \
              --description="Service account for Event Mill Cloud Run deployment" \
              --quiet 2>&1 >/dev/null); then
    echo "   ✓ Created: ${SA_EMAIL}"
else
    explain_error "Service account ${SA_EMAIL}" "${err}"
    FAILED=$((FAILED + 1))
fi
echo ""

# ---------------------------------------------------------------------------
# Section 4: Project-level IAM
# ---------------------------------------------------------------------------
# Bucket-level storage access is applied in Section 5 instead of project-level,
# to avoid conflicts with org policies that require conditional IAM bindings.
# ---------------------------------------------------------------------------
echo "🔐 Section 4: Project IAM..."

add_project_binding "serviceAccount:${SA_EMAIL}" "roles/logging.logWriter"
add_project_binding "serviceAccount:${SA_EMAIL}" "roles/cloudbuild.builds.editor"

# Cloud Build uploads source tarballs to GCS and pushes images to AR as the
# default compute service account.
if gcloud iam service-accounts describe "${DEFAULT_COMPUTE_SA}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    add_project_binding "serviceAccount:${DEFAULT_COMPUTE_SA}" "roles/storage.objectAdmin"
    add_project_binding "serviceAccount:${DEFAULT_COMPUTE_SA}" "roles/artifactregistry.writer"
else
    echo "   ⚠ Default compute SA not found: ${DEFAULT_COMPUTE_SA}"
    echo "     It is created when compute.googleapis.com is enabled; that may"
    echo "     take a minute to propagate. Re-run this script afterwards."
    WARNED=$((WARNED + 1))
fi

if gcloud iam service-accounts describe "${CLOUDBUILD_SA}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    add_project_binding "serviceAccount:${CLOUDBUILD_SA}" "roles/run.admin"
else
    echo "   ⚠ Legacy Cloud Build SA not found: ${CLOUDBUILD_SA} (may be fine)"
fi
echo ""

# ---------------------------------------------------------------------------
# Section 4b: actAs delegations
# ---------------------------------------------------------------------------
# Four distinct actAs relationships exist in this deployment. v1 configured
# only the two machine-to-machine ones (3 and 4) and silently omitted the two
# human-operator ones (1 and 2) — which is why a hand-run deploy fails twice
# with "Permission 'iam.serviceAccounts.actAs' denied", once per target SA.
#
#   1. operator          -> default compute SA   `gcloud builds submit`
#                                                (the build runs as that SA)
#   2. operator          -> eventmill-runner     `gcloud run deploy
#                                                 --service-account=...`
#   3. eventmill-runner  -> default compute SA   the running app submitting
#                                                Zeek Cloud Build jobs
#   4. Cloud Build SA    -> eventmill-runner     Cloud Build performing the
#                                                deploy (cloudbuild*.yaml)
#
# IAM is written HERE, at bootstrap, and only verified at deploy time. That
# keeps the deploy path free of IAM-write permission, so the same script works
# unchanged under a CI service account that must not be able to rewrite IAM.
# ---------------------------------------------------------------------------
echo "🎭 Section 4b: actAs delegations..."

# 1 + 2: the human (or CI identity) running the deploy script
if [ -n "${OPERATOR_MEMBER}" ]; then
    grant_actas "${DEFAULT_COMPUTE_SA}" "${OPERATOR_MEMBER}" \
        "operator can actAs default compute SA (gcloud builds submit)"
    grant_actas "${SA_EMAIL}" "${OPERATOR_MEMBER}" \
        "operator can actAs ${SA_NAME} (gcloud run deploy)"
else
    echo "   ⊘ Operator unknown — skipping operator actAs grants."
    echo "     A hand-run deploy will fail until these are granted; see README."
fi

# 3: Event Mill submits Zeek builds, which execute as the default compute SA
grant_actas "${DEFAULT_COMPUTE_SA}" "serviceAccount:${SA_EMAIL}" \
    "${SA_NAME} can actAs default compute SA (Zeek Cloud Build)"

# 4: Cloud Build deploying Cloud Run as the runtime SA
if gcloud iam service-accounts describe "${CLOUDBUILD_SA}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    grant_actas "${SA_EMAIL}" "serviceAccount:${CLOUDBUILD_SA}" \
        "Cloud Build SA can actAs ${SA_NAME} (CI deploy)"
fi
echo ""

# ---------------------------------------------------------------------------
# Section 5: GCS buckets
# ---------------------------------------------------------------------------
echo "📦 Section 5: Buckets (region: ${REGION})..."

LIFECYCLE_90D=$(mktemp /tmp/eventmill-lifecycle-90d.XXXXXX.json)
LIFECYCLE_365D=$(mktemp /tmp/eventmill-lifecycle-365d.XXXXXX.json)
trap 'rm -f "${LIFECYCLE_90D}" "${LIFECYCLE_365D}"' EXIT

printf '{\n  "rule": [\n    {"action": {"type": "Delete"}, "condition": {"age": 90}}\n  ]\n}\n'  > "${LIFECYCLE_90D}"
printf '{\n  "rule": [\n    {"action": {"type": "Delete"}, "condition": {"age": 365}}\n  ]\n}\n' > "${LIFECYCLE_365D}"

create_bucket_if_missing() {
    local bucket_name="$1" lifecycle_file="$2" description="$3" err="" loc=""

    if loc=$(gcloud storage buckets describe "gs://${bucket_name}" \
                --project="${PROJECT_ID}" --format="value(location)" 2>/dev/null); then
        # Warn on region drift instead of silently accepting it. Cross-region
        # reads work but pay egress on every file load.
        if [ -n "${loc}" ] && [ "${loc,,}" != "${REGION,,}" ]; then
            echo "   ⚠ gs://${bucket_name} exists in ${loc}, not ${REGION}"
            WARNED=$((WARNED + 1))
        else
            echo "   ✓ Exists: gs://${bucket_name} (${loc})"
        fi
    elif err=$(gcloud storage buckets create "gs://${bucket_name}" \
                  --project="${PROJECT_ID}" \
                  --location="${REGION}" \
                  --uniform-bucket-level-access 2>&1 >/dev/null); then
        echo "   ✓ Created: gs://${bucket_name}  (${description})"
    else
        explain_error "Bucket gs://${bucket_name}" "${err}"
        FAILED=$((FAILED + 1))
        return 1
    fi

    # Non-fatal: lifecycle and bucket IAM are best-effort, but report honestly.
    if ! err=$(gcloud storage buckets update "gs://${bucket_name}" \
                  --project="${PROJECT_ID}" \
                  --lifecycle-file="${lifecycle_file}" 2>&1 >/dev/null); then
        echo "     ⚠ lifecycle rule not applied"
        WARNED=$((WARNED + 1))
    fi
    if ! err=$(gcloud storage buckets add-iam-policy-binding "gs://${bucket_name}" \
                  --project="${PROJECT_ID}" \
                  --member="serviceAccount:${SA_EMAIL}" \
                  --role="roles/storage.objectAdmin" \
                  --quiet 2>&1 >/dev/null); then
        echo "     ⚠ objectAdmin not granted to ${SA_NAME}"
        WARNED=$((WARNED + 1))
    fi
}

for slug in "${PILLAR_SLUGS[@]}"; do
    create_bucket_if_missing "${BUCKET_PREFIX}-${slug}" "${LIFECYCLE_90D}" "${slug} artifacts"
done
create_bucket_if_missing "${BUCKET_PREFIX}-common" "${LIFECYCLE_365D}" "shared cross-pillar data"

# ---------------------------------------------------------------------------
# Common bucket folder placeholders
# ---------------------------------------------------------------------------
# This is the exact step that killed v1: `echo -n "" | gsutil cp - "${dest}"`
# with no guard, under `set -e`, with stderr discarded. Everything below it —
# Artifact Registry, secrets, secret IAM — was skipped without a single
# character of output. Here it is non-fatal and uses gcloud storage.
# ---------------------------------------------------------------------------
echo "   Initializing common bucket folders..."
init_common_folder() {
    local folder="$1"
    local dest="gs://${BUCKET_PREFIX}-common/${folder}/.keep"
    local err=""

    if gcloud storage objects describe "${dest}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
        echo "     ✓ ${folder}/"
        return 0
    fi
    if err=$(echo -n "" | gcloud storage cp - "${dest}" --project="${PROJECT_ID}" 2>&1 >/dev/null); then
        echo "     ✓ ${folder}/ (created)"
    else
        echo "     ⚠ ${folder}/ placeholder not created (non-fatal)"
        WARNED=$((WARNED + 1))
    fi
}

for folder in "${COMMON_FOLDERS[@]}"; do
    init_common_folder "${folder}"
done
init_common_folder "generated/threat_report_analyzer"
init_common_folder "exports"
echo ""

# ---------------------------------------------------------------------------
# Section 6: Artifact Registry — IN THE REQUESTED REGION
# ---------------------------------------------------------------------------
# The repo location is embedded in the image path
# (${REGION}-docker.pkg.dev/...), so this must match the deploy region exactly
# or `docker push` fails with: name unknown: Repository "eventmill" not found
# ---------------------------------------------------------------------------
echo "🐳 Section 6: Artifact Registry (region: ${REGION})..."

# Surface same-named repos in OTHER regions. v1 gave no hint that this was
# possible, which is what turned a region mismatch into a paid-build failure.
OTHER_LOCATIONS=$(gcloud artifacts repositories list --project="${PROJECT_ID}" \
    --format="value(name.basename(), location)" 2>/dev/null \
    | awk -v r="${AR_REPO}" -v reg="${REGION}" '$1 == r && $2 != reg { print $2 }')

if [ -n "${OTHER_LOCATIONS}" ]; then
    echo "   ⚠ A repo named '${AR_REPO}' already exists in other region(s):"
    echo "${OTHER_LOCATIONS}" | sed 's/^/       /'
    echo "     Artifact Registry repos are regional. This run targets ${REGION}."
    echo "     Images in the other region(s) are NOT reachable from ${REGION}."
    WARNED=$((WARNED + 1))
fi

if gcloud artifacts repositories describe "${AR_REPO}" \
        --project="${PROJECT_ID}" --location="${REGION}" >/dev/null 2>&1; then
    echo "   ✓ Already exists: ${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPO}"
elif err=$(gcloud artifacts repositories create "${AR_REPO}" \
              --project="${PROJECT_ID}" \
              --repository-format=docker \
              --location="${REGION}" \
              --description="Event Mill container images" \
              --quiet 2>&1 >/dev/null); then
    echo "   ✓ Created: ${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPO}"
else
    explain_error "Artifact Registry '${AR_REPO}' in ${REGION}" "${err}"
    echo "     Creating a repo needs artifactregistry.repositories.create."
    echo "     roles/artifactregistry.repoAdmin does NOT include it —"
    echo "     you need roles/artifactregistry.admin"
    echo "     (console: 'Artifact Registry Administrator', without 'Repository')."
    FAILED=$((FAILED + 1))
fi
echo ""

# ---------------------------------------------------------------------------
# Section 7: Secret Manager entries
# ---------------------------------------------------------------------------
# Created with a "placeholder" value; real values come from provision-secrets.sh
# ---------------------------------------------------------------------------
echo "🔑 Section 7: Secrets..."

for secret in "${SECRET_NAMES[@]}"; do
    if gcloud secrets describe "${secret}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
        echo "   ✓ Already exists: ${secret}"
    elif err=$(echo -n "placeholder" | gcloud secrets create "${secret}" \
                  --project="${PROJECT_ID}" \
                  --data-file=- \
                  --labels="app=eventmill" \
                  --quiet 2>&1 >/dev/null); then
        echo "   ✓ Created: ${secret} (placeholder — set via provision-secrets.sh)"
    else
        explain_error "Secret ${secret}" "${err}"
        FAILED=$((FAILED + 1))
    fi
done
echo ""

# ---------------------------------------------------------------------------
# Section 8: Secret IAM bindings — applied AND verified
# ---------------------------------------------------------------------------
# v1 printed "✓ <sa> can read <secret>" unconditionally because the binding
# call ended in `> /dev/null 2>&1` with no status check. Cloud Run refuses to
# create a revision if the runtime SA cannot read an injected secret, so a
# false success here becomes a confusing deploy failure later.
# ---------------------------------------------------------------------------
echo "🔗 Section 8: Secret access for ${SA_NAME}..."

for secret in "${SECRET_NAMES[@]}"; do
    if ! gcloud secrets describe "${secret}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
        echo "   ⊘ ${secret} does not exist — skipping binding"
        continue
    fi

    if ! err=$(gcloud secrets add-iam-policy-binding "${secret}" \
                  --project="${PROJECT_ID}" \
                  --member="serviceAccount:${SA_EMAIL}" \
                  --role="roles/secretmanager.secretAccessor" \
                  --quiet 2>&1 >/dev/null); then
        explain_error "Binding on ${secret}" "${err}"
        FAILED=$((FAILED + 1))
        continue
    fi

    # Verify rather than assume
    if gcloud secrets get-iam-policy "${secret}" --project="${PROJECT_ID}" \
            --format="value(bindings.members)" 2>/dev/null | grep -q "${SA_EMAIL}"; then
        echo "   ✓ ${SA_NAME} can read ${secret}  (verified)"
    else
        echo "   ⚠ ${secret}: binding applied but not visible yet (IAM is eventually consistent)"
        WARNED=$((WARNED + 1))
    fi
done
echo ""

# ---------------------------------------------------------------------------
# Section 9: Summary
# ---------------------------------------------------------------------------
echo "============================================="
if [ "${FAILED}" -eq 0 ] && [ "${WARNED}" -eq 0 ]; then
    echo "✅ Provisioning complete — no errors, no warnings."
elif [ "${FAILED}" -eq 0 ]; then
    echo "✅ Provisioning complete with ${WARNED} warning(s) — review above."
else
    echo "❌ Provisioning finished with ${FAILED} error(s) and ${WARNED} warning(s)."
    echo "   Unlike v1, this script did NOT abort early — every section ran."
    echo "   Fix the errors above and re-run; the script is idempotent."
fi
echo "============================================="
echo ""
echo "Project:         ${PROJECT_ID}"
echo "Region:          ${REGION}"
echo "Service account: ${SA_EMAIL}"
echo "Bucket prefix:   ${BUCKET_PREFIX}"
echo "Artifact repo:   ${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPO}"
echo ""
echo "Buckets:"
for slug in "${PILLAR_SLUGS[@]}"; do
    echo "   gs://${BUCKET_PREFIX}-${slug}"
done
echo "   gs://${BUCKET_PREFIX}-common"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "NEXT STEPS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  1. Set real secret values (they are 'placeholder' until you do):"
echo "       bash cloud_install/provision-secrets.sh"
echo ""
echo "  2. Pin the region and prefix so deploys cannot drift:"
echo "       cat >> ~/.eventmill/deploy.env <<EOF"
echo "       export GOOGLE_CLOUD_PROJECT=\"${PROJECT_ID}\""
echo "       export CLOUD_RUN_REGION=\"${REGION}\""
echo "       export EVENTMILL_BUCKET_PREFIX=\"${BUCKET_PREFIX}\""
echo "       EOF"
echo ""
echo "  3. Deploy (run from the repo root):"
echo "       bash cloud_install/deploy-cloudrun-secrets-v2.sh"
echo ""

[ "${FAILED}" -eq 0 ] || exit 1
exit 0
