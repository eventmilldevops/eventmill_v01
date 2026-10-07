# PCAP Ingest Trigger — Phase 2 Implementation Prompt

> This file is a self-contained prompt for an AI coding assistant working in a
> checkout of the `eventmill_v01` repository. Paste its contents (or point the
> assistant at this file) to implement Phase 2 of the automated PCAP ingestion
> pipeline. Phase 1 (`cloud_install/pcap_trigger/`) is already deployed and
> verified — it validates sensor_id and writes an acknowledgment marker, but
> does not invoke any Event Mill code.

---

## Context

Event Mill's actual investigation engine (`framework/session/`,
`framework/cloud/resolver.py`, the `network_forensics` plugin tools) is only
reachable today through the interactive shell:
`python -m framework.cli.shell` → `EventMillShell` → a `cmd.Cmd` REPL. The
deployed `event-mill` Cloud Run service (see `cloud_install/deploy-cloudrun.sh`
and `cloud_install/Dockerfile.cloudrun`) serves this shell over `ttyd`
(a websocket terminal) — it has no HTTP API a caller can invoke
programmatically.

Phase 2 adds a **second entrypoint** into the same engine (no duplication of
session/tool/storage logic) and a **second Cloud Run deployment** of the same
container image that exposes it over HTTP. The Phase 1 trigger is then
updated to call that new service whenever a PCAP is acknowledged, so the full
pipeline becomes: PCAP lands → Phase 1 validates + acks → Phase 2 runs the
investigation → results land back in GCS — with no human involved.

## Scope boundary — read this twice

- Do **not** touch `EventMillShell` command behavior or remove `ttyd`/the
  interactive shell. Analysts must keep using it exactly as today.
- Do **not** build the "mapping"/fingerprint command, baseline bookkeeping, or
  LLM-based anomaly comparison against history. Those are later phases
  (Phase 3+) and are out of scope here.
- Do **not** duplicate session/tool-execution logic. The new entrypoint must
  call the existing `SessionManager`, tool classes, and
  `StorageResolver.upload()`/`download()` — the same objects `shell.py`
  already uses.
- Keep the new HTTP entrypoint's business logic additive: new files plus
  small, targeted edits to `cloud_install/pcap_trigger/main.py` and the
  deploy scripts. Do not restructure `framework/session/` or
  `framework/cloud/`.

## What to build

### 1. Headless entrypoint (`framework/cli/api_server.py`)

A small FastAPI (or Flask) app exposing:

```
POST /analyze
{
  "pcap_uri": "gs://<bucket-B>/<sensor_id>/<filename>.pcap",
  "sensor_id": "ids-sensor-01",
  "tool": "pcap_ai_analyzer",       # default if omitted
  "mode": "triage_summary"          # tool-specific arg, default if omitted
}
```

Internally, for each request:
1. Create a new session via `SessionManager` (equivalent to shell's `new`).
2. Set `active_pillar = "network_forensics"` (equivalent to `pillar`).
3. Download the PCAP from `pcap_uri` via the existing GCS-backed
   `StorageResolver` and load/parse it (equivalent to `load <file>`,
   reusing `_auto_parse_pcap()` logic from `framework/cli/shell.py` —
   extract it to a shared helper if it's currently private to the shell
   class, rather than copy-pasting it).
4. Auto-connect the LLM client from `GEMINI_FLASH_API_KEY`/
   `GEMINI_PRO_API_KEY` env vars (no interactive `connect` step — this is
   the one new piece of initialization logic Phase 2 adds).
5. Run the requested tool (equivalent to `run <tool> --mode <mode>`).
6. Export the resulting artifact(s) to the common bucket via
   `StorageResolver.upload()` (equivalent to shell's `export`), under
   `common/exports/pcap_pipeline/<sensor_id>/<session_id>/`.
7. Return `{"session_id", "status", "result_uri"}` as JSON. Catch and log
   exceptions; return a structured error response rather than a raw 500
   with a stack trace.

Use `logging` (never `print`), full type hints, f-strings, PEP8/88-char
lines — matching this repo's conventions (see `framework/cli/shell.py` for
style reference).

### 2. Container entrypoint switch

Add an `EVENTMILL_MODE` env var (`shell` default, `api` alternative) checked
in `framework/__main__.py` (or wherever `Dockerfile`'s `CMD` resolves to) to
start `api_server.py` instead of `EventMillShell.cmdloop()` when
`EVENTMILL_MODE=api`. Do not change the default behavior when the var is
unset.

### 3. New deploy script (`cloud_install/deploy-cloudrun-api.sh`)

Modeled on `cloud_install/deploy-cloudrun.sh`: same image
(`${_REGION}-docker.pkg.dev/$PROJECT_ID/eventmill/event-mill:latest`, built
by the existing `build-event-mill.yaml` — no new build config needed), but:
- Deployed as a **separate Cloud Run service** (e.g. `event-mill-api`), not
  reusing the `event-mill` service name.
- `--set-env-vars="EVENTMILL_MODE=api"`.
- Larger `--memory`/`--cpu`/`--timeout` than the Phase 1 trigger function
  (LLM + PCAP parsing needs real resources and can run for minutes —
  Cloud Run services support up to 60-minute request timeouts).
- **No public access** — do not pass `--allow-unauthenticated`. Only
  `pcap-trigger-runner` (and any other explicitly approved identity) may
  invoke it, via `roles/run.invoker` scoped to this specific service.

### 4. Wire Phase 1 into Phase 2 (`cloud_install/pcap_trigger/main.py`)

After writing the ack marker with `status="acknowledged"` (skip this call
entirely for `"unmapped"` sensors — fail closed, same philosophy as Phase 1),
make an authenticated HTTP POST to `event-mill-api`'s `/analyze` endpoint:
- Fetch a Google-signed OIDC identity token for the target service URL
  (`google.auth.transport.requests` + `google.oauth2.id_token`) using the
  function's own runtime service account — no new secrets.
- POST `{"pcap_uri": f"gs://{bucket}/{object_name}", "sensor_id": sensor_id}`.
- This call should be **fire-and-forget with a short connect timeout**
  (e.g. a few seconds) rather than blocking on the full analysis — Phase 1's
  own function still has a short timeout budget. Log the call result
  (queued/error) but do not fail the trigger's own ack-writing if the
  analysis call itself fails; log and move on.
- Add the new HTTP client dependency (e.g. `google-auth`, `requests`) to
  `cloud_install/pcap_trigger/requirements.txt`.

### 5. IAM

- Grant `pcap-trigger-runner@<project>.iam.gserviceaccount.com` the
  `roles/run.invoker` role scoped to the `event-mill-api` Cloud Run service
  only (not project-wide, not the `event-mill` ttyd service).
- No changes needed to the `event-mill` (ttyd) service's existing IAM.

## Testing / exit criteria for this phase

- Local test: run `api_server.py` directly (`EVENTMILL_MODE=api` locally
  with local filesystem storage resolver), POST a sample `/analyze` request
  referencing a local test PCAP path, confirm a session is created, the tool
  runs, and an artifact is written to the local exports folder.
- Deploy `event-mill-api` and confirm `gcloud run services describe
  event-mill-api` shows `ACTIVE` with no public ingress.
- Re-run the Phase 1 exit-criteria PCAP upload (registered sensor); confirm
  the trigger's ack marker still gets written as before, **and** a new
  session/export directory shows up under
  `common/exports/pcap_pipeline/<sensor_id>/` in the common bucket shortly
  after.
- Confirm an unregistered-sensor upload does **not** trigger an `/analyze`
  call (check `event-mill-api` logs show no invocation for that event).
- Confirm the existing interactive `event-mill` (ttyd) service is completely
  unaffected — analysts can still run `new`/`pillar`/`load`/`run` manually.

## Security requirements

- `event-mill-api` must not allow unauthenticated invocations.
- Validate `pcap_uri` and `sensor_id` in the request body the same way
  Phase 1 does (regex-restricted `sensor_id`, path must resolve inside the
  expected bucket) before passing them to any file-loading code — treat the
  trigger's call as the only trusted caller, but still validate defensively
  since this endpoint accepts untrusted-shaped input over HTTP.
- No hardcoded credentials; identity tokens are fetched at call time from
  the calling function's own runtime service account.
- Fail closed: if the LLM auto-connect fails (missing API keys), the
  `/analyze` endpoint should return a clear structured error rather than
  silently running tools without LLM support where the tool requires it.
