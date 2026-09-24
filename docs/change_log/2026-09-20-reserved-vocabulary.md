# One place for the words the schemas already mean something by

**Date:** 2026-09-20
**Branch:** `llm_5`
**Scope:** documentation. New `docs/specs/reserved_vocabulary.md`; one row
added to CLAUDE.md's "Where to look".
**Status:** written. No code changed, suite unchanged at 1705.

## Why

`protocol: physical` was reserved while building the branch estate, and the
operator's observation was that it is not alone: `rdp`/3389, `mqtt`, `modbus`
and the rest each signify a *kind of interchange*, not merely a transport.
Spread across five schemas and three plugins, those meanings were folklore.
This document is where they live, and where future decisions of the same kind
get recorded.

## What it covers

Nine sections, each distinguishing **enforced** values (schema enums, closed
code catalogues, validators) from **reserved** ones (free text where a spelling
already carries meaning). The distinction is the point: an enforced value fails
loudly, a reserved one is accepted and quietly means something the author did
not intend.

- **Protocol vocabulary**, grouped by what the flow *is* rather than what
  carries it: human and out-of-band (`physical`, `lte`, `manual`), interactive
  sessions (`rdp` 3389, `ssh`, `winrm`, `tacacs`), application and data
  (`https`, `postgres`, `smb`, `ldap`, `kerberos`), messaging and industrial
  (`kafka`, `mqtt`, `modbus`, `opcua`, `dnp3`, `rtsp`). Each row says what its
  presence implies for detection — `mqtt` across a boundary is a telemetry-gap
  indicator, `modbus` has no authentication in the protocol at all, `physical`
  has no packet and is evidenced by badge and door sources.
- **The rule that the number goes in `port`**: `protocol: rdp, port: 3389`,
  never `protocol: "tcp/3389"`.
- Flow-map enums, projector access states and warning codes, the designer's
  origins, statuses and grades, the telemetry library's vocabularies and `EM-`
  namespaces, control function, manifest enums, and identifier prefixes
  (`art_`, `drf_`, `AE-####` which restarts per scenario, `SC-####`).
- **Three standing rules**: never invent an identifier (`DS####` forbidden
  outright); widening an enum is a behaviour decision, not a typo fix; absent
  is not null and null is not zero.
- **A debugging table by symptom** — a value accepted with no effect, every
  plugin failing validation at once, an unreachable crown jewel, a grade lower
  than expected, an assessment element that is constant, an em dash that became
  a hyphen.

## Checked rather than recalled

Every enum was read from its schema or module before being written down:
manifest enums from `manifest_schema.json`, flow-map enums from
`flow_map.schema.json`, `ACCESS_STATES` and `COMPONENT_SCOPED_STATES` from the
projector, the designer's code catalogue and origins from
`normalization.py`, the library's vocabularies from `telemetry_library.py`.
The projector's codes were enumerated from its source, and the first draft of
this entry **conflated two families** — `UNREACHABLE_CROWN_JEWEL` and its
neighbours are `validate_flow_map` findings about the map, while `STATE_GAP`
and `TACTIC_CORRECTED` are projection warnings that live in the run record. The
document now separates them, and records that the run-record family is not
joined to nodes because one fixture pair has no run record.

Two known-wrong values are documented as such rather than quietly fixed:
`stability: stable` in 15 manifests, and the capability-namespace pattern that
rejects underscores. Both govern visibility or invoke policy, so both are
behaviour decisions.
