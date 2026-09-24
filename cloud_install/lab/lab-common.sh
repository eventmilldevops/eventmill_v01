#!/bin/bash
# =============================================================================
# Event Mill — training lab, shared configuration
# =============================================================================
#
# Sourced by the other lab-*.sh scripts, never run directly. One place states
# how an instance number N maps to a service, a login and two secrets, so the
# build, provision, deploy, verify and teardown scripts cannot drift apart.
#
# Default lab: 18 services, N = 2..19, each login shared by two students
# (36 seats). Override the range with FIRST / LAST.
#
#   N = 7  ->  service   event-mill-7   (two students)
#              login     yeg7.bsides
#              secrets   eventmill-ttyd-user-7, eventmill-ttyd-cred-7
#
# The password prefix is NOT in this file. It is a credential, and a committed
# pattern is a committed password. Put it in ~/.eventmill/lab.env:
#
#   LAB_PASSWORD_PREFIX='...'      # single quotes: the value may contain '#'
#
# Only lab-provision-secrets.sh and lab-verify.sh need it.
#
# lab-build-image.sh records the image tag it built in
# ~/.eventmill/lab-image.env; lab-deploy.sh deploys exactly that tag.
# =============================================================================

# Deploy config first, exported, so every child process sees the same project,
# region and bucket prefix. lab-deploy.sh then stops deploy-cloudrun-secrets.sh
# from re-sourcing it, because a re-source would overwrite the per-instance
# values the lab sets.
EVENTMILL_DEPLOY_ENV="${EVENTMILL_DEPLOY_ENV:-${HOME}/.eventmill/deploy.env}"
if [ -f "${EVENTMILL_DEPLOY_ENV}" ]; then
    _pre_project="${GOOGLE_CLOUD_PROJECT:-}"
    _pre_region="${CLOUD_RUN_REGION:-}"
    _pre_prefix="${EVENTMILL_BUCKET_PREFIX:-}"
    set -a
    # shellcheck disable=SC1090
    . "${EVENTMILL_DEPLOY_ENV}"
    set +a
    [ -n "${_pre_project}" ] && GOOGLE_CLOUD_PROJECT="${_pre_project}"
    [ -n "${_pre_region}" ]  && CLOUD_RUN_REGION="${_pre_region}"
    [ -n "${_pre_prefix}" ]  && EVENTMILL_BUCKET_PREFIX="${_pre_prefix}"
    export GOOGLE_CLOUD_PROJECT CLOUD_RUN_REGION EVENTMILL_BUCKET_PREFIX
    unset _pre_project _pre_region _pre_prefix
    echo "Loaded deploy config: ${EVENTMILL_DEPLOY_ENV}"
fi

EVENTMILL_LAB_ENV="${EVENTMILL_LAB_ENV:-${HOME}/.eventmill/lab.env}"
if [ -f "${EVENTMILL_LAB_ENV}" ]; then
    # shellcheck disable=SC1090
    . "${EVENTMILL_LAB_ENV}"
    echo "Loaded lab config:    ${EVENTMILL_LAB_ENV}"
fi

PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-}"
REGION="${CLOUD_RUN_REGION:-}"
SA_NAME="${EVENTMILL_SA_NAME:-eventmill-runner}"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
AR_REPO="${EVENTMILL_AR_REPO:-eventmill}"

# The image every lab instance runs: its own repository path, separate from
# the primary event-mill image, so rebuilding the primary service never
# changes what the lab is running. Built by lab-build-image.sh, which pins
# the tag in LAB_IMAGE_ENV; lab-deploy.sh never builds.
LAB_IMAGE_NAME="${LAB_IMAGE_NAME:-event-mill-lab}"
LAB_IMAGE_BASE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPO}/${LAB_IMAGE_NAME}"
LAB_IMAGE_ENV="${LAB_IMAGE_ENV:-${HOME}/.eventmill/lab-image.env}"
if [ -z "${LAB_IMAGE_TAG:-}" ] && [ -f "${LAB_IMAGE_ENV}" ]; then
    # shellcheck disable=SC1090
    . "${LAB_IMAGE_ENV}"
fi
LAB_IMAGE_TAG="${LAB_IMAGE_TAG:-}"

FIRST="${FIRST:-2}"
LAST="${LAST:-19}"

LAB_SERVICE_PREFIX="${LAB_SERVICE_PREFIX:-event-mill-}"
LAB_USER_PREFIX="${LAB_USER_PREFIX:-yeg}"
LAB_USER_SUFFIX="${LAB_USER_SUFFIX:-.bsides}"
LAB_PASSWORD_PREFIX="${LAB_PASSWORD_PREFIX:-}"

lab_service()     { printf '%s%s' "${LAB_SERVICE_PREFIX}" "$1"; }
lab_user()        { printf '%s%s%s' "${LAB_USER_PREFIX}" "$1" "${LAB_USER_SUFFIX}"; }
lab_password()    { printf '%s%s' "${LAB_PASSWORD_PREFIX}" "$1"; }
lab_secret_user() { printf 'eventmill-ttyd-user-%s' "$1"; }
lab_secret_cred() { printf 'eventmill-ttyd-cred-%s' "$1"; }

lab_require_project() {
    if [ -z "${PROJECT_ID}" ]; then
        echo "ERROR: GOOGLE_CLOUD_PROJECT is not set (and no ${EVENTMILL_DEPLOY_ENV})."
        exit 1
    fi
}

lab_require_region() {
    if [ -z "${REGION}" ]; then
        echo "ERROR: CLOUD_RUN_REGION is not set. It must match the region"
        echo "       the primary event-mill service was deployed in."
        exit 1
    fi
}

lab_require_password_prefix() {
    if [ -z "${LAB_PASSWORD_PREFIX}" ]; then
        echo "ERROR: LAB_PASSWORD_PREFIX is not set."
        echo "       Put it in ${EVENTMILL_LAB_ENV}, single-quoted:"
        echo "         LAB_PASSWORD_PREFIX='...'"
        exit 1
    fi
}

# FIRST..LAST must be plain integers, in order. N is embedded in service and
# secret names, so anything else would name resources nobody meant to touch.
lab_require_range() {
    if ! [[ "${FIRST}" =~ ^[0-9]+$ && "${LAST}" =~ ^[0-9]+$ ]]; then
        echo "ERROR: FIRST and LAST must be integers (got '${FIRST}', '${LAST}')."
        exit 1
    fi
    if [ "${FIRST}" -gt "${LAST}" ]; then
        echo "ERROR: FIRST (${FIRST}) is greater than LAST (${LAST})."
        exit 1
    fi
}

# Report a gcloud failure with what gcloud actually said.
lab_report_error() {
    local label="$1" err="$2"
    echo "   ✗ ${label}"
    echo "${err}" | sed 's/^/       /'
    if echo "${err}" | grep -qi "not available in your location"; then
        echo "       Google geo-blocked this client IP; see AGENTS.md."
    fi
}
