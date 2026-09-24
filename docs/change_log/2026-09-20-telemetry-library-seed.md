# The telemetry reference library, seeded and validated

**Date:** 2026-09-20
**Branch:** `llm_5`
**Scope:** code and reference data. New
`framework/reference_data/telemetry_library.json` (v0.1.0) and
`telemetry_library.py`; 24 tests in `tests/framework/test_telemetry_library.py`;
`framework/reference_data/README.md`; spec §8 and header.
**Status:** built. Suite **1681 → 1705**. Nothing consumes the library yet —
the designer join is G1 work.

## What was built

34 observation sources covering the five example estates: claims portal 7,
telemetry SaaS 9, plant OT 6, branch office 12, loyalty commerce 14 (several
are shared, and `collector.heartbeat` serves all five). Each entry records what
the source emits, its native and derived fields, what is **absent without
enrichment**, what collecting it requires, its artefact, cadence, latency and
owner, and what it observes.

**Every `collection.status` reads `unknown`,** deliberately. The entries
describe what these products and processes emit; no real estate has been
surveyed against them, and recording `confirmed` would be the exact failure
§0 warns about — assuming a control produces evidence.

## What the loader refuses to let drift

`validate_library()` returns a list of problems and the suite asserts it is
empty. Three rules matter more than the rest:

- **An ATT&CK id is never invented.** Every `exact` and `adjacent` mapping is
  checked against the local v19.2 release, including its matrix, and
  `unmapped` must carry a local `EM-` id with a rationale and **no**
  `attack_id`. Two candidate ids were dropped while writing the data because
  the check failed them: `T1562.001` (retired) and `T0855` (absent from the
  local ICS set).
- **`adjacent` must say how it differs.** A `relation_kind` from the declared
  vocabulary plus a rationale, or validation fails. That is what stops a badge
  grant being filed as `T1078`.
- **A `decision_support` entry may not claim a detection.** Tested directly:
  those entries must carry `supports` edges, and any observation they make must
  be `unmapped`. Counting an asset register as a detection would overstate
  every supporting source in the estate.

## What the data says that a log-only library could not

- **15 unmapped behaviours** with local ids — physical presence at a door
  (`EM-PHYS-0001`), restricted-space entry, a fraud score (`EM-FRAUD-0002`), a
  liability variance, a victim-reported loss, a toxic role combination
  (`EM-PROC-0004`), a silent telemetry source (`EM-PROC-0005`).
- **Both audits are `variance_management`, not attack detection.** The
  quarterly hardware audit finds an implant because the rack stopped matching
  the register, up to 90 days later; the monthly badge review asks whether
  rights have drifted. A test pins both, because recording them as `monitoring`
  is what lets a draft imply they watch for an intruder.
- **CCTV is `on_request` with a `human_readable` artefact**, and its note says
  plainly that it is response support rather than detection.
- **NetFlow's note says it cannot see the cellular path**, which is the whole
  point of the branch estate: the implant's exfiltration never traverses the
  exporter.
- **Three decision-support entries**: the role assignment export that makes
  dual approval evaluable (`enables_trigger`), the asset register that turns an
  unknown MAC into a named device, and the redemption baseline that supplies a
  threshold instead of a guess.
- **Separation of duties is recorded as a join**, not an event:
  `ledger.adjustment_audit` carries `join_keys` naming the actor and approver
  fields and stating that one artefact holds both.
- **The Kubernetes rule is enforced by test.** `kubernetes.api_audit` lists
  in-container file reads under `absent_without_enrichment` and does **not**
  claim `T1552.001`; `container.file_access` does. A draft proposing a
  mounted-token read detection with only API audit declared cannot pass.

## Deliberately not done

- **No `EM-AGENT-` entries.** The operator has not decided whether agent
  telemetry belongs in the seed, and the seed is otherwise limited to the five
  estates. §4.3 keeps the case recorded.
- **No consumer.** Nothing joins the library to a node yet; that is G1,
  along with `telemetry_readiness` as an axis separate from
  `context_completeness`.
- **No collection survey.** Every status is `unknown` until a real estate is
  walked.

## Verified, and not

- 24 library tests, full suite 1705 passing.
- Counts in this entry and in §8 of the spec are the loader's output, not
  estimates.
- Every ATT&CK id in the file was checked against the local release before the
  file was written, and again by `validate_library()`.
- `ruff`, `black` and `mypy` are not installed in this environment.
