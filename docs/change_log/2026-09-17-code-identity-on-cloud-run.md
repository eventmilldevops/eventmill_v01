# Code identity survives into the container

**Date:** 2026-09-17
**Branch:** `llm_5`
**Scope:** `plugins/threat_modeling/adversary_path_projector/tool.py`,
its `schemas/projection_run.schema.json` and `tests/test_contract.py`,
`cloud_install/deploy-cloudrun-secrets.sh`
**Status:** built and unit-tested. Suite **1519 → 1523**. Not yet exercised by
a deploy.

A projection run from the Cloud Run container wrote:

```json
"tool_version": { "manifest_version": "0.2.0", "git_sha": "" }
```

`_git_short_sha()` walks the module's parent directories for a `.git` and reads
`HEAD`. A deployed image has no `.git` at all, so the walk finds nothing and
returns the empty string it was initialised with. The function was behaving
correctly; the export was the thing that came out wrong.

Two problems follow, and they compound:

1. **The manifest version does not move.** That is deliberate and documented —
   it has read 0.2.0 since the projection action landed, while several
   behaviour changes shipped under it — and the whole reason `git_sha` exists
   is to be the field that separates two runs of different code. On Cloud Run
   it is empty, so a container's export has **no code identity whatsoever**.
   That is the one platform where the operator cannot go and look at the
   working tree instead.
2. **Empty is ambiguous.** `""` read the same whether the identity was
   unavailable or the field had simply never been populated.

## What changed

**The deploy forwards the SHA it already has.** `deploy-cloudrun-secrets.sh`
computes `IMAGE_TAG` from `git rev-parse --short HEAD` to tag the image with,
and then dropped it. It is now passed to the service as
`EVENTMILL_BUILD_SHA`, and `_git_short_sha()` reads that before attempting the
`.git` walk.

Deliberately **only on the path that builds the image.** Under `SKIP_BUILD=1`
the script redeploys `:latest`, and `IMAGE_TAG` would still hold the *local*
tree's SHA — forwarding it there would attach an identity to an image this tree
did not produce. `BUILD_SHA` stays empty on that path and the runtime records
`unavailable`, which is the honest answer. `IMAGE_TAG` falls back to a UTC
timestamp when git is unavailable at build time; that is forwarded, since it
still identifies the image that was built.

**`code_id_source` says where the SHA came from** — `git_worktree`,
`build_env` or `unavailable` — in both exports and the run record, so an empty
`git_sha` can no longer be confused with an unpopulated one. Added to
`projection_run.schema.json` as an optional property; the schema has no
`additionalProperties` restriction, and older records simply lack it.

## Verified

Four new tests: `EVENTMILL_BUILD_SHA` takes precedence over the working tree
and reports `build_env`; the working tree is used and reported as
`git_worktree` when the variable is unset; no git and no variable reports
`unavailable` with an empty SHA — the Cloud Run case; and both exports and the
run record agree on the same SHA and source in one run.

One existing test was updated rather than worked around:
`test_record_carries_both_version_identifiers` asserted the `tool_version`
block held exactly two keys. It now expects three and checks the enum, which
keeps its point — the manifest version alone cannot separate two builds.

Full suite 1523 passed; `bash -n` clean on the deploy script;
`validate_schemas.py` clean at 34.

**Not done:** no deploy has run, so `EVENTMILL_BUILD_SHA` has never been set by
the real script — only by tests. The next Cloud Run deploy is what confirms it,
and the check is one line: a projection export from the container should read
`code_id_source: build_env` with the image tag in `git_sha`. Exports written by
the container *before* that deploy keep their empty SHA and no
`code_id_source`, and cannot be retrofitted.
