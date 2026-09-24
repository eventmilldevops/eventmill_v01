# Reserved vocabulary — the words the schemas already mean something by

Status: living reference, started 2026-09-20. One place to look before
inventing a value, and the first place to look when a plugin behaves as though
it ignored one.

Every value here is either **enforced** (a schema enum, a validator, a closed
catalogue in code) or **reserved** (the field is free text, but these spellings
already carry meaning and must not be redefined). The distinction matters when
debugging: an enforced value fails loudly, a reserved one is accepted and
quietly means something you did not intend.

---

## 0. The three rules behind everything below

1. **Never invent an identifier.** `T####`, `T0###`, `M####`, `G####`, `S####`
   and `C####` come from the local ATT&CK release and are checked against it.
   `DS####` data components are **forbidden outright** — no local reference
   carries them, so any that appear were supplied from a model's memory.
   Native event ids (Windows `4624`, pgAudit `AUDIT: OBJECT`) are quoted
   exactly as the product emits them, or the event is described with
   `mapping_status: description_only`. A described event with no id is correct;
   an invented id is a defect.
2. **Widening an enum is a behaviour decision, not a typo fix.** Two live
   examples: 15 plugin manifests declare `stability: stable`, which the schema
   does not define, and the capability-namespace pattern rejects underscores.
   Both stand unfixed on purpose, because the values govern visibility and
   invoke policy.
3. **Absent is not null, and null is not zero.** A field a source could not
   supply is omitted; a field that was measured as empty is present and empty.
   `tag_caveat: null` with no reason would read as "every control is tagged",
   which is why it carries `tag_caveat_reason`.

---

## 1. Flow map — `protocol` (free text, reserved spellings)

`protocol` is a free string by design: no enum can anticipate an estate. These
spellings are reserved because the projector, the designer and the telemetry
library read meaning from them. **Use the port field for the number** —
`protocol: rdp, port: 3389`, never `protocol: "tcp/3389"`.

Each entry below says what the flow *is*, not merely what carries it, because
that is what a detection has to observe.

### Human and out-of-band

| Protocol | Typical port | What it signifies |
|---|---|---|
| `physical` | — | **A person moving through space**, not a packet. Reserved 2026-09-20. `authenticated: false` where tailgating or an unenforced escort defeats the check; `true` where a badge, key or signature is required. No network sensor observes it; its evidence is badge, door-alarm and CCTV sources (`EM-PHYS-`). |
| `lte` / `cellular` | — | An out-of-band carrier path. Reachability that **bypasses every estate egress control**, so proxy, DLP and firewall telemetry are all blind to it by construction. |
| `manual` | — | A human-carried transfer: a USB device, a printout, a dictated credential. Leaves an artefact only if some process records it. |

### Interactive and administrative sessions

| Protocol | Typical port | What it signifies |
|---|---|---|
| `rdp` | 3389 | Interactive Windows desktop session. A human at a keyboard, or something pretending to be one; session start/end and the source address are the observable unit. |
| `ssh` | 22 | Interactive or automated shell session. Command-level visibility requires a session manager or host agent, not the protocol. |
| `vnc` | 5900 | Interactive desktop session without Windows session semantics. |
| `winrm` | 5985 / 5986 | Remote Windows administration. Command execution without an interactive logon type. |
| `tacacs` / `radius` | 49 / 1812 | Device administration authentication. Its accounting records are often the only log a network device produces. |

### Application and data

| Protocol | Typical port | What it signifies |
|---|---|---|
| `https` / `http` | 443 / 80 | Application request traffic. `http` additionally means **unencrypted**, which is a finding in itself on an internal flow. |
| `grpc` | 443 (usual) | Structured RPC. Method-level visibility needs application telemetry; a proxy sees only the stream. |
| `postgres` / `mysql` / `mssql` | 5432 / 3306 / 1433 | Database session. Connection logs answer *who*; statement auditing (pgAudit and equivalents) answers *what*, and is a separate collection decision. |
| `smb` | 445 | File share access. Object-level auditing is enabled per share, so coverage is a property of configuration rather than of the product. |
| `ldap` / `ldaps` | 389 / 636 | Directory query or bind. `ldap` unencrypted on an internal flow is a credential-exposure finding. |
| `kerberos` | 88 | Ticket issuance. The domain-wide view of account use. |
| `s3` / `object` | 443 | Object store access. Read and list operations are the unit, not files. |
| `smtp` | 25 / 587 | Mail transfer. Frequently the exfiltration path nobody models. |
| `dns` | 53 | Name resolution, and a covert channel when it is not. |

### Messaging, telemetry and industrial

| Protocol | Typical port | What it signifies |
|---|---|---|
| `kafka` | 9092 / 9093 | Publish/subscribe stream. Authorisation decisions are observable; message contents are not, without a separate consumer. |
| `amqp` | 5672 | Message queue interchange, point-to-point or fanout. |
| `mqtt` | 1883 / 8883 | **Lightweight publish/subscribe, typical of OT, IoT and field telemetry.** Frequently unauthenticated or shared-credential, often bridged across a boundary, and rarely logged by the broker in a way that identifies a publisher. Presence of `mqtt` across a trust boundary is a telemetry-gap indicator, not merely a transport note. |
| `modbus` | 502 | Industrial control, **no authentication in the protocol**. Anything that can reach it can command it. |
| `opcua` | 4840 | Industrial control with optional security. Whether it is authenticated is a deployment fact, never a protocol fact. |
| `dnp3` | 20000 | Industrial telemetry and control, common in utilities. |
| `s7comm` / `bacnet` | 102 / 47808 | Vendor-specific control protocols; building automation for the latter. |
| `rtsp` | 554 | Camera or media stream. Usually means a physical-security system is on this network. |
| `snmp` | 161 | Device management and polling. Write communities are an administration path. |
| `ethernet` | — | A link, not a service: a wall port, patch or uplink. Its presence says a device can be attached, which is what makes it interesting in a physical path. |

**Adding a protocol.** Use the product's own name in lowercase, put the number
in `port`, and add a row here if another tool should read meaning from it.

---

## 2. Flow map — enforced enums

Defined in `plugins/threat_modeling/adversary_path_projector/schemas/flow_map.schema.json`.

| Field | Values |
|---|---|
| `component.type` | `web_app`, `api`, `service`, `database`, `datastore`, `queue`, `cache`, `identity_provider`, `gateway`, `load_balancer`, `cdn`, `file_store`, `workstation`, `server`, `container_platform`, `ci_cd`, `secrets_manager`, `external_service`, `actor`, `admin_console`, `network_device`, `other` |
| `component.exposure` | `internet`, `partner`, `internal`, `management` — **who can reach it directly**. No physical value exists; a public lobby is recorded `internet`, which is semantically wrong and structurally right. |
| `zone.trust_level` | `untrusted`, `semi_trusted`, `trusted`, `restricted` (`restricted` is the most protected) |
| `component.data_classification` | `public`, `internal`, `confidential`, `pii`, `regulated`, `secret` |
| `control.control_type` | `perimeter`, `network`, `endpoint`, `application`, `data`, `identity`, `monitoring` — **anatomy, not function.** No physical, process or business class exists; see §6 for the function axis that complements it. |
| `control.implementation_status` | `implemented`, `partial`, `planned`, `missing` |
| `control.bypass_difficulty` | `trivial`, `low`, `medium`, `high`, `very_high` |
| `control.detection_capability` | `none`, `low`, `medium`, `high` — **capability, not cadence.** A quarterly manual audit and a live alarm can both be `medium`; the telemetry library carries the difference. |

---

## 3. Projector — attack path vocabulary

| Field | Values and meaning |
|---|---|
| `access_before` / `access_after` | `none`, `network_reach`, `code_execution`, `user_credential`, `service_credential`, `privileged`, `data_access`. **Component-scoped:** `network_reach`, `code_execution`, `privileged`, `data_access` are held *on one component*; credentials are portable and travel with the attacker. |
| `state_check` | `ok`, `gap`. A `gap` means the path needs access no earlier step establishes. It is never argued away downstream. |
| `state_note` | Free prose, joined to `state_check` by **U+2014 EM DASH with one space either side** in the scenario seed. A hyphen or en dash is a transport defect, not a content disagreement. |
| `evidence` | `documented`, `via_software` |
| `actor_support` | `procedure_documented`, `technique_documented`, `via_software` |
| `transition` shape | `{entry: true, exposure}`, `{flow, from, to, protocol, authenticated, crosses_boundary, return?}`, or `null` |
| Projection warnings (run record) | `STATE_GAP`, `TACTIC_CORRECTED`, `HOP_NOT_DECLARED`, `LATE_INITIAL_ACCESS`, `KILL_CHAIN_REGRESSION`, `TECHNIQUE_NOT_IN_SET`, `ASSUMPTIONS_TRUNCATED`. They key on `<path_id>.steps[<n>]`, live in the run record rather than the exports, and are **not** joined to nodes by the designer — one fixture pair has no run record, so they can never be a required input. |
| Flow-map validation warnings | `UNREACHABLE_CROWN_JEWEL`, `ISOLATED_COMPONENT`, `ENTRY_NOT_EXPOSED`, `NO_EXTERNAL_EXPOSURE`, `SELF_FLOW`, `DUPLICATE_FLOW`, `DANGLING_FLOW_ENDPOINT`, `UNKNOWN_ZONE`, `UNKNOWN_CROWN_JEWEL`, `UNKNOWN_MITIGATION`. Returned by `validate_flow_map`, about the map rather than any projection. |

---

## 4. Detection designer — normalization vocabulary

Catalogue of warning, review-flag and error codes: §4.4 of
`docs/specs/attack_path_detection_normalization.md`. Emitting an undeclared
code raises rather than inventing one.

| Field | Values |
|---|---|
| `provenance_by_field.origin` | `graph`, `seed`, `pair_agreed`, `flow_map`, `reference_data`, `derived`. A `derived` entry carries `basis` (the fields it was computed from) in place of a pointer. |
| `pair.provenance_status` | `verified`, `derived`, `conflict`, `single_source` |
| `pair.pair_join` | `run_id`, `asserted_by_operator`, `refused`, `not_attempted` |
| `flow_map.lineage` | `same_map`, `edited_map`, `unhashed`. **Lineage, never a gate** — an edited map is an expected input. |
| `context_completeness` | `component_bound`, `component_bound_partial`, `asset_named`, `asset_text_only`, `unbound` |
| `transition.movement` | `entry`, `declared_flow`, `in_place`, `undeclared`, `unparsed`. `in_place` and `undeclared` are both `null` in the export, told apart by whether the component changed. |
| `transition.evidence` | `structured` (the graph's object), `text` (parsed from the seed's prose; never promoted) |
| `monitoring_claim` | `none`, `partial`, `claimed` — a claim about what is watched, **never coverage** |
| `technique_status` | `current`, `retired_remapped`, `unresolved`. A remap adds `technique_id_current`; the export value is never rewritten. |
| `tactic_status` | `as_supplied`, `reconciled`, `unresolved` |
| Warning `severity` | `blocking` (the output omits or downgrades something), `advisory` (complete, but read it) |
| Assessment reason codes | `group_technique_documented`, `software_technique_documented`, `not_established_in_local_sources`, `no_actor_attack_id_in_export`, `inherited_state_gap`, `undeclared_transition`, `predecessors_supply_required_access`. `access_state_modelled_not_declared` is a **qualifier, never a trigger** — it is true on every node, so triggering on it produced a constant. |

---

## 5. Telemetry library

Defined in `framework/reference_data/telemetry_library.py`, specified in
`docs/specs/telemetry_reference_library.md`.

| Field | Values |
|---|---|
| `category` | `log`, `audit`, `alert_feed`, `report`, `reconciliation`, `physical_record`, `human_report` |
| `availability.artefact` | `machine_readable`, `human_readable`, `human_report`, `none` |
| `availability.cadence` | `continuous`, `daily`, `weekly`, `monthly`, `quarterly`, `on_request` |
| `collection.necessity` | `required`, `alternative`, `enrichment` |
| `collection.status` | `confirmed`, `assumed`, `missing`, `unknown` — **independent of necessity**: a source can be required and missing |
| `events[].mapping_status` | `native_identifier`, `description_only` |
| `attack_relation` | `exact`, `adjacent`, `unmapped` |
| `relation_kind` (on `adjacent`) | `broader`, `narrower`, `precursor`, `consequence`, `variant` |

### Local identifier namespaces

Never ATT&CK-shaped, and registered here so nothing needs renaming later.

| Namespace | Domain |
|---|---|
| `EM-PHYS-####` | Physical access and tamper |
| `EM-OT-####` | Process and safety |
| `EM-FRAUD-####` | Value and business logic |
| `EM-PROC-####` | Human procedure, duty separation and control drift |
| `EM-INSIDER-####` | Authorised-actor misuse |
| `EM-AGENT-####` | Autonomous agents under delegated authority. **Reserved, unused** — identified for future development only |

---

## 6. Control function (FAIR-CAM axis)

Complements `control_type` (§2), which describes where a control sits.

| `control_function.domain` | Meaning |
|---|---|
| `loss_event` | Acts on the event: prevents, detects or responds |
| `variance_management` | Keeps other controls working; finds drift. A quarterly asset audit detects that the estate stopped matching its register, **not** that an attack occurred |
| `decision_support` | Informs choices so other controls fire correctly. Detects nothing on its own |

| `supports[].effect` | Meaning |
|---|---|
| `enables_trigger` | Without this data the control cannot evaluate at all |
| `tunes_threshold` | Sets or corrects a boundary the control applies |
| `provides_context` | Lets an alert be judged rather than merely raised |
| `verifies_operation` | Confirms the control still runs as intended |

**Scope:** classification only. No loss magnitude, frequency or control value —
this pillar is detection engineering and threat modelling, not quantification.

---

## 7. Plugin manifest

`docs/specs/manifest_schema.json`, `additionalProperties: false` — an
unregistered field fails validation for **every** plugin at once.

| Field | Values |
|---|---|
| `stability` | `experimental`, `verified`, `core`, `deprecated` (**not** `stable`, which 15 manifests declare) |
| `timeout_class` | `fast`, `short`, `medium`, `slow`, `long` |
| `model_tier` | `light`, `heavy`, `none` — reasoning depth and cost, **never** how much data fits |
| `cost_hint` | `low`, `moderate`, `high` |
| `capabilities` | `namespace:value` pairs; the pattern currently rejects underscores in the namespace |

### Provider tier capabilities

Not the plugin field above: these are the bare tokens in each tier's
`capabilities` list in `framework/llm/providers/<id>.json`. The dispatcher
routes on them, and plugins act on what it reports, so a token must be true
of the **client as built**, not just the model. A test fails any provider that
declares `native_pdf` while its client refuses documents.

| Token | Meaning |
|---|---|
| `text` | Text in, text out |
| `multimodal_image` | The model accepts images (no plugin calls `query_multimodal` yet) |
| `native_pdf` | The client sends a PDF to the model natively; the plugins plan page-range batches on it |
| `remote_uri_gs` | The client reads a `gs://` URI itself. **Absent** means the dispatcher reads the bytes first (OpenAI, Anthropic) |
| `structured_output` | JSON-mode capable |
| `function_calling` | Tool calls |
| `deep_reasoning` | Heavy-tier reasoning model |

---

## 8. Identifier prefixes

| Prefix | Issued by | Meaning |
|---|---|---|
| `art_` | the shell's artifact registry | A registered artifact, session-scoped |
| `drf_` | the detection designer | A deterministic draft id from `(projection_identity, path_id, node_index)` |
| `AE-####` | the projector's scenario seed | Event id, **restarts at `AE-0001` in every scenario** — never a global key |
| `SC-####` | the projector's scenario seed | Control id within a scenario's catalogue |
| `EM-*-####` | this repository | Behaviours outside ATT&CK (§5) |

---

## 9. Adding a word

1. Say what it means here, in one line, before using it.
2. If a schema enum must change, treat it as a behaviour change with its own
   entry in `docs/change_log/` — not a typo fix.
3. Free-text fields (`protocol`, `authentication`, `technologies`) take new
   values freely; add a row here only when another tool should read meaning
   from the spelling.
4. Closed code catalogues (designer warnings, errors, review flags) are
   declared in code and mirrored in the spec; tests hold the two together.

## 10. Debugging by symptom

| Symptom | Likely cause |
|---|---|
| A value was accepted and nothing happened | Free-text field, unreserved spelling. Check §1 — `protocol: "tcp/3389"` is not `rdp`. |
| Validation fails for every plugin at once | An unregistered manifest field; `additionalProperties: false`. |
| A crown jewel reports unreachable | No flow reaches it — including physical entry, which needs `protocol: physical` (§1). |
| A grade is lower than expected | The map was not supplied, or the component id did not resolve in it. The hash is lineage and never affects grading. |
| Every node carries the same assessment value | A constant is not an assessment — check whether the trigger field is set on every node, as `access_source: model` is. |
| A mitigation or technique id is "unknown" | It is genuinely absent from the pinned release. It is reported, never guessed or ranked at an assumed breadth. |
| An em dash became a hyphen | Transport encoding, not a content conflict. Raises `STATE_NOTE_ENCODING`. |
