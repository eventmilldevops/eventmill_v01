# 2026-08-30 — `files` gains filters, metadata, and `#N` references

`files` printed every object in the pillar bucket plus the common bucket,
unsorted and untruncated, with no way to narrow it:

```
  Filename                                 Source     Path
  ──────────────────────────────────────── ────────── ──────────────────────────
  auth.log                                 pillar     linuxdroplettest/auth.log
```

Against a real backing store that is unusable. The analyst scrolls back through
the terminal to find a row, then hand-copies the path into `load` or a `run`
flag. Two things were missing — a way to narrow the listing, and any handle on a
row other than its path string.

## The listing

```
files [--path <prefix>] [--ext .log,.json] [--newer 24h]
      [--match <pattern>] [--sort time|size|name] [--limit N]
```

`--path` is pushed down to the backend as an object prefix; `--ext`, `--newer`
and `--match` filter in the shell. Ordering defaults to newest first, capped at
50 rows with a `... and N more` footer.

Two details are deliberate rather than incidental:

`--ext .log` matches against **every** suffix, not the last one, so it finds
`auth.log.1` as well as `auth.log`. Matching `Path.suffix` would have made the
rotated-log set in this project's own guide invisible to the flag that exists to
find it.

`--newer` takes a count and a unit — `90m`, `24h`, `7d`, `2w`. Compound forms,
calendar units, and a bare number are rejected with a message naming the valid
units rather than guessed at.

## `#N`

Every row is numbered, and `#N` stands in for a file wherever one is expected.
The index is over the rows **as displayed**, after filtering, sorting and
limiting, so `#3` always means the third line just printed.

`#N` expands to a different string per command, because the three consumers want
three different things. `load` and `zeek` get the row's exact
`gs://bucket/object_path` URI, which routes straight to `_resolve_explicit` and
skips re-resolution entirely — this also sidesteps a latent bug where a pasted
`object_path` was re-prefixed with the workspace folder, missed, and only
resolved because the bucket-root fallback happened to catch it. Plugin tools
read local files, so `run` gets the local artifact path instead.

`run <tool> --path #3` on a file that has not been loaded is an **error**, not an
implicit download:

```
  #3 is a stored file (linuxdroplettest/auth.log.1), not a local one.
  Load it first:  load #3
```

Auto-loading would bury an arbitrarily large transfer inside `run`, with no
`--fast` control, no artifact-type override, and a session artifact appearing as
a side effect. The error names the one command that fixes it.

Only a value that is exactly `#N` is treated as a reference, so `--query "#3"`
is untouched; `##3` escapes to a literal `#3`. Expansion happens per flag value
rather than in `precmd` for that reason — a global rewrite would corrupt
legitimate `#` values in queries and regexes.

A listing is validated against the `(session, pillar, workspace_folder)` it was
taken under, at the point of use rather than by eagerly clearing it on every
context change. A stale reference is refused and says what moved:

```
  #3 was listed under log_analysis;
  you are now in log_analysis:linuxdroplettest. Run 'files' again.
```

## Metadata, and two bugs found on the way

Size and modification time were available at both backends and thrown away.
`LocalStorageBackend` already held a `Path`; `GCSStorageBackend` already received
populated `Blob` objects from `list_blobs`. `StorageBackend.list_files_detailed`
is concrete rather than abstract, defaulting to name-only entries, so no
implementer breaks. Timestamps are normalised to aware UTC **at the backend
boundary** — GCS returns aware datetimes and `st_mtime` is a naive float, so
comparing them for `--newer` would have raised `TypeError` only on GCS, only in
Cloud Run, and in no test.

`list_workspace` deduplicated by **basename**, which silently hid files: with no
workspace folder set, `inc-1/auth.log` and `inc-2/auth.log` collapsed to one row
and one of them was invisible. That is the exact rotated-log-per-incident layout
this pillar is used for. Deduplication now follows the two rules resolution
itself uses — by `object_path` within a bucket, by basename only across buckets,
preserving pillar-shadows-common. Users with same-named files in several folders
will see more rows than before; that is the fix, not a regression.

`StorageResolver._list` never passed `max_results`, so every listing was
truncated at the backend default of 1000 with no indication. Shell-side filters
over a silently truncated list do not merely under-report — GCS returns
lexicographic order, so `--newer 24h` would have been systematically biased
against files late in the alphabet and could have confidently reported nothing.
The cap is now 5000 and is surfaced when it bites.

## Scope

`framework/cloud/interfaces.py` — `StoredObject`, `list_files_detailed`.
`framework/cloud/local/storage.py`, `framework/cloud/gcp/storage.py` — overrides.
`framework/cloud/resolver.py` — `WorkspaceFile`, `WorkspaceListing`, the dedup
rule, prefix push-down, `_list` → `_list_detailed`.
`framework/cli/shell.py` — `do_files` and its helpers, `_resolve_file_ref`,
`_expand_file_refs`, `complete_files`; the `--key value` tokeniser was factored
out of `_parse_flag_payload` into `_split_flags` rather than copied.

`tests/framework/test_cli_files.py` is new and is the first test of
`EventMillShell` — `#N` is stateful behaviour across commands that no resolver
test can reach, and the staleness rule would rot silently without one.
