# 2026-09-08 — `files` scopes to the pillar and explains itself

An analyst in `threat_modeling` ran this and reasonably concluded the tool was
broken:

```
eventmill (threat_modeling) > files --path threat_modeling
  No files found in threat_modeling or common bucket.
  Prefix filter: threat_modeling
```

Nothing was broken. `--path` is pushed down to the backend as an **object key
prefix**, and a pillar name never appears in an object key — the pillar *is* the
bucket (`bucket_for_pillar()` → `eventmill-threat-modeling`). The keys in that
bucket start with `reports/`. Zero matches was the correct answer to the
question that got asked.

That is the whole problem: the command assumed knowledge of a two-bucket layout
and a folder hierarchy that a SOC analyst has no way to see. There was no view
of the layout, and an empty result said only that it was empty.

## Scope: `--source`

```
files [--source pillar|common|all]
```

The default is now `pillar` — the analyst's own investigation data, which is
what they came for. `common` holds shared reference data plus tool output under
`exports/` and `generated/`, and is one flag away.

A narrowed default is only safe if it never looks like the whole picture, so a
listing that hid something says so, with the filters applied to the count:

```
  4 more files in the common bucket: generated/, vendor_advisories/
  Add --source all to include them.
```

## Layout: `--folders`

Nothing in the shell showed how storage was laid out, so there was no way to
guess what `--path` would accept. `--folders` prints the map instead of the
files, one level below `--path`, per bucket:

```
  pillar bucket — evtm-threat-modeling
    reports/                              1 file  738.3 KB

  common bucket — evtm-common
    exports/                              1 file    4.2 KB
    vendor_advisories/                   3 files   57.9 MB
```

Files sitting directly at the listed level are grouped under `(files here)`
rather than dropped, so a bucket with everything at the root still maps to
something. When that is all a level holds there is nothing to drill into, so the
footer offers a listing instead:

```
eventmill (threat_modeling) > files --path vendor_advisories --source all --folders
  common bucket — evtm-common
    (files here)                           4 files   60.2 MB

  No folders below this one.
  List what is here: files --path vendor_advisories --source all
```

An empty map goes through the same explanation the file listing does, with
`--folders` carried into every command it suggests — otherwise `--folders`
dead-ends on exactly the case it exists to rescue:

```
eventmill (threat_modeling) > files --path vendor_advisories --folders
  Nothing under 'vendor_advisories' in the threat_modeling pillar bucket.
  4 files match in the common bucket:
  files --path vendor_advisories --source all --folders
```

## Empty results teach

An empty listing now names where it looked and what is actually there. Four
cases, in precedence order:

- `--path` was given the current pillar, its slug, or its bucket name → say that
  the pillar already selects the bucket and that `--path` names a folder below it
- `--path` was given `common` or another pillar → point at `--source common` or
  `pillar <name>`
- the prefix matches in the *other* bucket → print the count and the exact
  command, `files --path reports --source all`
- otherwise → a `difflib` near-miss suggestion, then the folders that do exist

The last one needs a second, unprefixed `list_workspace` call: the first listing
was filtered at the backend, so it cannot say what else is there. That costs one
extra list only on the empty path, where the analyst is already stuck.

If nothing at all is visible, the message points at the bucket prefix rather
than the filters — an empty `EVENTMILL_BUCKET_PREFIX` reads buckets that do not
exist and fails silently, which looks identical to a bad `--path`.

## Not changed

`list_workspace()` still hides a common-bucket file whenever its **basename**
matches any pillar-bucket file, at any depth (`resolver.py`), while within a
bucket dedup is by full path. With `--source common` now an explicit request,
that asymmetry is more visible than it was. Comparing full object paths across
buckets would keep pillar-wins for genuine collisions without the collateral,
but it is a behaviour change to the resolver rather than a fix to `files`, so it
is left alone here.
