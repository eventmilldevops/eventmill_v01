# Change Log — the run record names the vendor that answered

**Date:** 2026-09-14
**Primary Files Modified:**
`plugins/threat_modeling/adversary_path_projector/tool.py`,
`plugins/threat_modeling/adversary_path_projector/schemas/projection_run.schema.json`,
`plugins/threat_modeling/adversary_path_projector/schemas/output.schema.json`,
`plugins/threat_modeling/adversary_path_projector/tests/test_contract.py`

**1080 tests pass** (was 1075; +5). Stage C of
`docs/specs/projector_three_vendor_run.md`. `RUN_RECORD_SCHEMA_VERSION` 3 → 4.

---

## What this fixes

Stages A and B made it possible to run the projector on three vendors in one
session. Until this landed, all three records said the same thing:

```python
"model": {
    "provider": "gcp_gemini",     # hardcoded, tool.py:3506
```

That was true while one vendor could be bound and silently false the moment two
could. A group of nine records from three vendors would have been not an
incomplete measurement but a **false** one — and nothing in the record would
have shown it.

Three vendors, one group, after:

```
v4  provider=gcp_gemini  served=gcp_gemini-heavy-001  prompt=a1338eb8f0c0  map=528d3c7a84eb
v4  provider=anthropic   served=anthropic-heavy-001   prompt=a1338eb8f0c0  map=528d3c7a84eb
v4  provider=openai      served=openai-heavy-001      prompt=a1338eb8f0c0  map=528d3c7a84eb
```

Same estate, same question, three reasoners — and the record proves all three
clauses rather than asserting them.

## The change

**`model.provider` is read from the response**, never assumed:

```python
"provider": getattr(response, "provider_id", None),
```

The tool cannot know which vendor served it — the operator's choice rides the
scoping wrapper, which a plugin deliberately cannot see — so the response is
the only honest source. The dispatcher stamps `provider_id` as a backstop when
a client omits it, so this is present on any real run; **null means no response
came back at all**. Defaulting to a vendor name would be worse than null: a
reader cannot tell a guess from an observation, and a wrong guess is what this
stage exists to remove.

**`run.prompt_sha256` is new.** SHA-256 over the system context and the prompt
body together — the system context is half of what was asked, and a change
there moves the answer as surely as a change to the body. Two records sharing a
`flow_map_sha256` are *not* necessarily comparable: `max_paths`,
`software_scope` or the actor resolution can move without touching the estate.
The hash is what lets a later reader check that, rather than take it on trust.

**The single-run result carries `provider` too**, so an operator comparing
vendors reads it off the run instead of opening the exported record. Not added
to `summarize_for_llm()`: which vendor answered is an operator's fact, not
something downstream reasoning should condition on, and that surface is capped
at 2000 characters.

## The prompt really is byte-stable, and that is now checked

The whole comparison rests on the prompt being identical across vendors. Two
tests hold it — one that the hash moves when `max_paths` moves, one that two
invocations asking the same thing produce byte-identical prompts.

An in-process test cannot catch the failure that would matter most, because
`PYTHONHASHSEED` is fixed for the life of a process: anything in the prompt
ordered by set iteration would be stable within a run and vary between runs.
Checked directly, across three seeds:

```
seed 0      a1338eb8f0c07304590740c06cad1cee636bde456d9c128f4dbf20b59dbd2b3a
seed 12345  a1338eb8f0c07304590740c06cad1cee636bde456d9c128f4dbf20b59dbd2b3a
seed 99999  a1338eb8f0c07304590740c06cad1cee636bde456d9c128f4dbf20b59dbd2b3a
```

Nothing set-ordered reaches the prompt. That was an assumption the plan rested
on and it is now a measurement.

## Schema

Both JSON schemas were edited as text rather than re-serialised. A
`json.load` / `json.dumps` round-trip expanded every compact one-line object in
the file and turned an 11-line change into 360 — and on Windows, reading them
without `encoding="utf-8"` mangles the em dashes in the descriptions. Worth
recording because the obvious tool is the wrong one here.

- `run.prompt_sha256` — `["string", "null"]`, null on pre-v4 records.
- `model.provider` — now `["string", "null"]`, with the description saying
  plainly that a v3 record's provider is an assumption rather than an
  observation.
- The `model` block's description said *"Gemini only; a second provider is a
  separate path and this block does not attempt to abstract over one."* It is
  now provider-neutral, which is the whole point of the stage.
- `output.schema.json` gains `provider`.

`python scripts/validate_schemas.py` — 34 schemas, all valid. (It needs
`PYTHONIOENCODING=utf-8` on Windows, as `CLAUDE.md` says.)

## A test bug worth naming

`test_the_prompt_hash_moves_when_the_question_does` failed first time, and the
code was right. It read the newest record with `_records_in(...)[-1]` twice;
record filenames carry a whole-second timestamp, so two runs inside the same
second sort by their uuid fragment and the "newest" record was the same file
both times — two identical hashes, and an apparent bug in `_prompt_hash`. Both
multi-run tests now assert on the prompts the fake model actually received,
which is the property being claimed and does not depend on filesystem ordering.

## Verified

- **1080 passed**, none skipped, none xfailed. 247 in the projector's own suite.
- End to end offline: `use <vendor> for adversary_path_projector` three times
  in one session against one flow map, three records written, each naming the
  vendor that served it, all three sharing a prompt hash.
- `ruff` / `black` / `mypy` are not installed in this venv, so none was run.

## Found while testing, not fixed here

**`run --file_path C:\Users\...` silently loses its backslashes.**
`_parse_flag_payload` uses `shlex.split(raw)` in POSIX mode, where a backslash
is an escape character, so `C:\Users\dleece\map.json` arrives as
`C:Usersdleecemap.json` and the tool reports `ARTIFACT_UNREADABLE` naming the
mangled path. Quoting the value works, and so do forward slashes. Pre-existing
and unrelated to this stage, but it is on the path to the Stage E run and this
is a Windows operator.

## Not done — Stage D

`_summarize_run_group` still has no provider dimension, so a mixed group's
recurrence threshold counts nine runs from three vendors as one population:
three samples from one vendor would outvote two other vendors. The records now
carry everything that stage needs.
