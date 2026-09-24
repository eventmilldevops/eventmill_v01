# One plugin for normalization and generation, and why the free action loses its flag

**Date:** 2026-09-17
**Branch:** `llm_5`
**Scope:** planning only. `docs/specs/attack_path_detection_normalization.md`
— §2 (the `safe_for_auto_invoke` claim corrected and a "where it lives"
paragraph added), §6 (where N1's code lands), §8 decision 7, §9. No code
changed, no tests run, no LLM call made.
**Status:** decided by the operator. **N1 is unblocked** — this was the last of
the two decisions that gated it.

## The decision

`normalize_paths` and `generate_detections` are **two actions of one plugin**,
and that plugin declares `safe_for_auto_invoke: false`.

## Why the question existed

§2 declared `normalize_paths` as `safe_for_auto_invoke: true` — reasonable on
its face, since the action is deterministic, provider-free and costs nothing.
But the manifest cannot express it. `safe_for_auto_invoke` is one boolean per
**plugin**: `docs/specs/manifest_schema.json` has no `actions` property and
sets `additionalProperties: false`, and `PluginManifest.__init__`
(`framework/plugins/loader.py:67`) reads a single boolean. A plugin that also
holds a heavy-tier generation call cannot be marked auto-invocable, so §2 was
unimplementable as written.

The decision could not be deferred to N4, where the action is specced, because
it determines how many plugin directories exist — and that determines where the
normalization library physically lives, which is N1's first line of code.

## Why one plugin rather than two

Decision 2 (§8) says `generate_detections` accepts a raw export as well as a
pack. So **both** actions need the normalization library.

**No plugin in this repository imports another.** The loader imports each under
a flat module name (`eventmill_plugin_<pillar>_<tool>`) specifically to avoid
parent-package lookups; a tree-wide check confirms plugins share code only
through `framework.*` — `reference_data`, `protocol`, `llm`, `documents`,
`logging`. A two-plugin split therefore forces one of three things, and none is
worth a flag nothing reads:

- move detection-specific normalization into `framework/`, which holds
  cross-cutting infrastructure rather than one feature's logic;
- duplicate the library, which guarantees the two copies diverge; or
- reverse decision 2 so generation only ever accepts a pack — a bigger change
  than the flag, and one that removes a deliberate convenience.

## What it costs, and why that cost is currently zero

A free, deterministic action sits in a plugin the manifest does not mark
auto-invocable, and the router gets one catalog entry rather than two, so
normalization is not independently discoverable.

**Nothing in the framework reads `safe_for_auto_invoke`.** A tree-wide search
for `auto_invoke` returns the assignment in `loader.py`, the same line in the
stale `build/` copy, and test assertions — nothing else. The routing modules
score on `capabilities`, `tags`, `artifacts_consumed`, `chains_to` and
`also_useful_in`; the flag is not among them. It is declarative intent today,
not a live gate, so the loss is documentary rather than behavioural.

This is also not a novel shape. `adversary_path_projector` already mixes free
deterministic actions (`profile_actor`, `validate_flow_map`) with a heavy-tier
`project_paths` under a single `safe_for_auto_invoke: false`. The cheap actions
have always paid for the expensive one's flag.

## What was rejected, and what would reopen it

Widening the manifest schema with a per-action flag was rejected **for now, not
on principle**. It is a change to visibility and auto-invoke policy, not a
typo fix; `additionalProperties: false` means an unregistered field fails
validation for every plugin at once; and with no caller reading the field there
is nothing to design the semantics against. That is the same reasoning that
forbids widening the `stability` enum to silence the validator — 15 of 16
manifests still fail it, and that is a behaviour decision left open
deliberately.

If `safe_for_auto_invoke` becomes a live gate and this action is the case that
demonstrates per-action granularity is needed, that is the moment to make the
change, with a real caller to test it against.

## Consequences for N1

N1 may create the plugin directory and manifest up front under
`plugins/threat_modeling/`, even though `normalize_paths` itself is N4 work;
the adapters are ordinary modules beside `tool.py` until then. The
normalization library is plugin-local and may not be imported by any other
plugin. Documentation of the action should say it is safe and free to run, and
should not claim the manifest says so.

## Verified

`manifest_schema.json` parsed (38 top-level properties, no `actions`,
`additionalProperties: false`); `loader.py:67` read; `auto_invoke` searched
across the tree, including tests and `build/`; the routing modules' manifest
field usage enumerated; cross-plugin imports searched for and absent; the
projector manifest read for the precedent. No code changed, no test run,
nothing committed.
