# 2026-09-23 — Training lab: 18 Cloud Run services, 36 seats

A training lab needs 18 services, `event-mill-2` to `event-mill-19`. Each has
its own ttyd login (`yegN.bsides`), shared by two students. Everything else is
shared: one pinned image, the LLM key secrets, the buckets and the runtime
service account.

## Decisions

| Question | Decision |
|---|---|
| Size | 18 login sets, 18 services, N = 2..19; two students per login |
| Scaling | `max-instances=2` per service, `min-instances=0` unless `LAB_MIN_INSTANCES` is set |
| Capacity | 18 × 2 × 2 vCPU = **72 vCPU** at full scale-out, against a 100 vCPU project quota. The primary `event-mill` adds up to 6 more. |
| ttyd credentials | Secret Manager: 36 secrets, `eventmill-ttyd-user-N` / `eventmill-ttyd-cred-N` |
| Daybreak key | Not mounted on lab services, and dropped from their provider list |
| Image | A dedicated `event-mill-lab` image built by a script and deployed by pinned tag |

The first draft of this entry planned 31 services with one student each and
`max-instances=1`. It was revised the same day, before anything was deployed.

Two students per service works because the deploy script's concurrency of 5
lets both connect to one container, and ttyd starts a separate shell process
for each connection. The second instance is headroom for when one container gets
busy. Each container has 2 GiB, and two concurrent PDF ingests is the likeliest
thing to exhaust it.

## Why a dedicated, pinned image

Before this change, the lab would have run `event-mill:latest`, the primary
service's image. Any rebuild of the primary service would then have changed
the code for every lab service the next time it was redeployed or restarted.
`lab-build-image.sh` builds `event-mill-lab:<sha>` and records the tag in
`~/.eventmill/lab-image.env`. `lab-deploy.sh` refuses to run without that tag
and deploys exactly it, so all 18 services run the same build.

The tag reaches the runtime as `EVENTMILL_BUILD_SHA`, the same way a normal
build's tag does. The projector keeps only the first 12 characters, so a
`<sha>-dirty-<stamp>` tag would be recorded as `<sha>-dirt`. The build
therefore **refuses** uncommitted changes in the paths the image copies
(`framework/`, `plugins/`, `pyproject.toml`, `README.md`) unless
`ALLOW_DIRTY=1` is set. Uncommitted docs or `cloud_install/` edits don't block
it, because they never reach the image. If a clean image with that SHA already
exists, the build is skipped; `FORCE=1` rebuilds.

The build steps mirror Step 6 of `deploy-cloudrun-secrets.sh`: the same
Dockerfile, and the repo root as the build context. A change to one must be
made in the other too.

## Changes to `deploy-cloudrun-secrets.sh`

The image path was built from the service name. So a lab service named
`event-mill-7` either rebuilt the image for itself or, with `SKIP_BUILD=1`,
looked for an `event-mill-7:latest` that does not exist. Five overrides were
added. Each defaults to the previous behaviour, so the primary deploy is
unchanged (checked with a stubbed `gcloud`):

- `EVENTMILL_IMAGE_NAME`: defaults to the service name.
- `EVENTMILL_IMAGE_TAG`: with `SKIP_BUILD=1`, deploys that tag instead of
  `:latest` and forwards it as `EVENTMILL_BUILD_SHA`. A pinned tag is the
  identity of the build that produced it. Reusing `:latest` still forwards
  nothing.
- `CLOUD_RUN_MIN_INSTANCES` / `CLOUD_RUN_MAX_INSTANCES`: default 0 / 3.
- `EVENTMILL_MOUNT_DAYBREAK`: default 1. When set to 0, the Daybreak secret
  isn't mounted, the default provider list drops both Daybreak ids, and naming
  either id explicitly is refused.

## New: `cloud_install/lab/`

Run in this order:

| Script | Does |
|---|---|
| `lab-build-image.sh` | Builds and pushes `event-mill-lab:<sha>` with Cloud Build and pins the tag. Deploys nothing and touches no secrets. |
| `lab-provision-secrets.sh` | Creates each secret pair, or adds a version if the value changed, and grants `secretAccessor` to `eventmill-runner`. The grant is here because the deploy script writes no IAM. |
| `lab-deploy.sh` | Checks that the pinned image and all the secrets exist, then runs the deploy script once per N. Optional `PARALLEL`. Writes per-service logs and rebuilds the roster (service, URL, login) from Cloud Run. |
| `lab-verify.sh` | Expects 401 without credentials and 200 with that service's own login. |
| `lab-teardown.sh` | Deletes the lab services and their secrets, after confirmation. It keeps the lab image, the primary service, the shared secrets and the buckets. |

`lab-common.sh` maps N to the service, login and secret names in one place.

The password prefix is **not in the repo**. It is read from
`~/.eventmill/lab.env` (`LAB_PASSWORD_PREFIX='...'`, single-quoted). Values
reach gcloud and curl on stdin, never in argv. Under the driver, the deploy
script's prompts read from `/dev/null`, so a "Deploy anyway?" condition aborts
that one service instead of hanging the run.

## Checked

- `bash -n` on all seven scripts.
- A stubbed `gcloud` across the full sequence:
  - Deploying before any build is refused.
  - The build tags `event-mill-lab:<sha>` and `:latest` and records the tag.
  - A dirty `framework/` refuses the build; `ALLOW_DIRTY=1` produces a
    `-dirty-` tag.
  - An existing image is reused.
  - Provisioning creates each secret pair with values stored exactly (`#`
    intact) and grants the runtime SA access.
  - The deploy uses the pinned image, sets `max-instances=2`, forwards
    `EVENTMILL_BUILD_SHA`, and mounts four LLM keys plus that service's ttyd
    pair.
  - The default range is 2..19, with a peak of 72 vCPU.
- `sh -c` expansion of a password containing `#`, the way
  `Dockerfile.cloudrun` passes it. It survives.

**Not run against GCP.** The first real check is `lab-verify.sh` after a deploy.

## Before the lab

- 36 students share one set of LLM keys. Check the per-key RPM/TPM limits.
- The buckets are shared, so students may see each other's artifacts.
- The services are public, and ttyd basic auth with a predictable pattern is the
  only protection. Run teardown straight after the lab.
