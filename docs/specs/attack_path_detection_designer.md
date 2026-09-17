# Attack Path Detection Designer — implementation plan

Status: proposed; no plugin implementation in this change.

Add `attack_path_detection_designer` to the `threat_modeling` pillar. Its
`generate_detections` action accepts an adversary path graph or scenario seed
and writes a Markdown detection workbook containing one self-contained YAML
detection draft for **each node occurrence in each path**. Each title starts
with its ATT&CK technique ID. Put a Markdown horizontal divider between drafts
so each fenced YAML block can be copied into its own file.

The detection is designed from the actor's documented behavior, the behavior
described at this node, the target component, and the node's position in the
chain. A technique ID alone is insufficient. All drafts start as
`new_unchecked`: existing controls or rules do not establish coverage until a
proper detection catalogue can be consulted.

Retain the supplied path as written. Add an expandable assessment tuple to
every detection, initially `actor_evidence` and `multistep_access`, alongside
the prose explaining gaps and assumptions. Downstream utilities can use these
fields to annotate or color the corresponding diagram node without rewriting
the path or interpreting free text.

## 1. Review of the supplied exports

Reviewed these files under `C:/projects/eventmill_v02/test_data/path_projector/`:

- `exports_adversary_path_projector_adversary_path_graph_20260915_165537.json`
- `exports_adversary_path_projector_adversary_scenario_seed_20260915_165537.json`

Both describe **APT29 (G0016)** against the **Fleet Telemetry Platform**. The
three path IDs, all 15 technique IDs, and their target assets match in order
between the graph and scenario export. There are 11 distinct technique IDs.

| Path | Ordered techniques | Drafts required |
|---|---|---:|
| `partner-key-to-vault` | T1199 → T1078 → T1021.007 → T1528 → T1078.004 | 5 |
| `pipeline-to-vault` | T1078.004 → T1195.002 → T1059.006 → T1105 → T1528 | 5 |
| `console-to-warehouse` | T1595.002 → T1190 → T1505.003 → T1528 → T1078 | 5 |

The graph's nodes are stored in `attack_graph.paths[].steps[]`; it is not a
`nodes`/`edges` graph. The scenario equivalent is
`scenarios[].attack_sequence[]`. Do not generate from `mitre_mappings`: that
list loses node occurrence, component, and sequence context.

The graph supplies component IDs, structured transitions, access states,
assumptions, control context, and actor procedure excerpts. The scenario
supplies event IDs, sequence numbers, target asset names, and similar context,
but loses the component ID and turns the transition and state check into text.
Scenario event IDs restart at `AE-0001` in each path; they are not globally
unique.

Neither export embeds the complete component technology inventory or a
telemetry configuration. The repository's
`plugins/threat_modeling/adversary_path_projector/examples/telemetry_saas_flow_map.json`
contains a matching application example, useful for this review. A future run
must accept such a map explicitly and record its provenance; a matching
application name is not proof that a map produced a particular export.

### Findings that should affect detection design

1. **Two different T1078 detections are necessary.** The partner path uses a
   Kafka SASL/SCRAM service principal for persistence. The console path uses
   the console's database identity to access PostgreSQL data from an allowed
   source. Windows logon events and a generic unusual-IP rule would miss the
   defining behavior in these examples.
2. **Actor evidence does not prove this deployment-specific procedure.** The
   T1078 excerpt concerns a compromised VPN account. Applying that behavior
   to Kafka or PostgreSQL is an adaptation. The T1195.002 support comes via
   SUNSPOT; retain `via_software`, rather than strengthening it to a directly
   documented attack on this pipeline.
3. **Two access-state gaps already exist**, at `pipeline-to-vault` steps 3
   (Python on the runner) and 5 (T1528 on Vault). The first concerns source
   control acting for the attacker; the second demands execution on Vault
   even though the narrative describes remote requests from the runner.
   Preserve these warnings. A state check of `ok` elsewhere proves only the
   projector's access continuity, not exploit feasibility.
4. **A partner API key is not automatically a Kafka credential.** The first
   path assumes the attacker can recover the ingest tier's separate SCRAM
   identity. Record that unresolved acquisition step; do not equate two
   instances of `service_credential` with the same credential.
5. **The Kafka-to-pod step needs technique review.** Its T1021.007 label is
   paired with exploitation of a message consumer, whereas its actor excerpt
   concerns movement into cloud services using compromised identities.
   Detect the described consumer behavior, retain the supplied label, and
   flag the mapping. Missing network policies alone do not execute a message.
6. **Separate Vault transport, authentication, token issuance, and secret
   access.** The runner's unauthenticated HTTP flow does not itself establish
   permission to read secrets. Kubernetes JWT login is also distinct from
   mTLS and yields a Vault token when correctly configured. Resolve the auth
   method and role mapping before treating this as a token-theft detection.
   See [Vault Kubernetes authentication](https://developer.hashicorp.com/vault/docs/auth/kubernetes)
   and [Vault login](https://developer.hashicorp.com/vault/docs/commands/login).
7. **T1528 does not make every credential an application token.** The console
   step mixes OIDC tokens with database client certificates/private keys.
   Select telemetry for the actual credential type, with a mapping warning
   where it is unknown. Ordinary secret reads on the runner-to-Vault path
   are not by themselves evidence of application access-token theft.
8. **Several feasibility claims are unverified.** A Node.js vulnerability is
   assumed, not identified by the cited appliance CVEs. A runtime web-shell
   file surviving container replacement requires persistent storage or an
   altered deployment artifact. The assertion that a high-bypass-difficulty
   WAF is readily bypassable is also unsupported. Carry these assumptions
   into the drafts rather than turn them into facts.

All 15 nodes still receive a draft section. Questionable mappings receive
`needs_mapping_review`; a missing observation mechanism receives a telemetry
gap. Neither condition justifies silently omitting a node or inventing an event.

## 2. Input and output contracts

Proposed invocation, after implementation:

```text
run attack_path_detection_designer --action generate_detections --file_path "C:/projects/eventmill_v02/test_data/path_projector/exports_adversary_path_projector_adversary_path_graph_20260915_165537.json"
```

The same command accepts the scenario seed filename. With session artifacts,
use `--artifact_id <id>` instead. Quotes and forward slashes avoid the current
CLI's Windows backslash parsing problem.

| Input | Contract |
|---|---|
| `action` | `generate_detections`; a deterministic `validate_input` action can share normalization and report expected node count without calling an LLM. |
| `artifact_id`, `file_path`, or `input_data` | Exactly one primary source. Accept the supplied graph wrapper, scenario wrapper, or a single scenario with `attack_sequence`. |
| `input_kind` | `auto`, `attack_graph`, or `scenario`; auto-detect by structure and reject ambiguous documents. |
| `path_ids` | Optional selection; default all paths. Unknown or duplicate path IDs are validation errors. Report selected and excluded counts. |
| `flow_map_artifact_id` | Optional component/platform/authentication enrichment, checked against the selected path components. Record unmatched assets and conflicts. |
| `telemetry_profile_artifact_id` | Optional products, versions, collected streams, native field mappings, retention, join keys, approved operations, and baseline availability. |
| `intel_artifact_ids` | Optional actor reports or evidence packets with source references. These enrich procedure context without adding path nodes. |
| `companion_artifact_id` | Optional corresponding graph/seed. Join only after validating actor, application, path IDs, order, techniques, and assets; flag disagreement rather than silently merge. |

Graph-only and scenario-only operation are first-class requirements. Missing
optional inputs reduce specificity and leave explicit assumptions; they do not
prevent the basic workbook. Never invent a cloud provider from `alb`, use the
Event Mill hosting provider as the assessed application's provider, or infer a
Linux/Windows event family from a technique ID.

Output artifacts:

- `attack_path_detections_<timestamp>_<run_id>.md`: the analyst workbook.
- `attack_path_detections_<timestamp>_<run_id>.json`: the same validated records,
  source hashes, provenance, generation attempts, and completeness accounting.

The JSON sidecar makes the Markdown reproducible and gives a future catalogue
an importable structure. Use existing artifact types `text` and `json_events`
with specific `metadata.kind` values; a new framework artifact enum is not
necessary. Return both through `ToolResult.output_artifacts` and registration.

The workbook begins with actor, application, input identity, ATT&CK version,
generation status, and a node coverage table. Then render every selected path
and node in source order. Each node section contains a suggested filename and
one complete `yaml` fenced block. Put `---` **outside** the fence between
sections. Copying a block produces one independent YAML document, including
its assumptions and source references.

Include the same assessment tuple and supporting reasons in each YAML block,
the JSON sidecar record, and the workbook's node coverage table. Downstream
consumers join assessments to the original node occurrence using its source
identity, `path_id`, and `node_index`; a technique ID alone is not a join key.

## 3. Normalize node identity without losing context

> **Superseded in part by
> `docs/specs/attack_path_detection_normalization.md` (2026-09-16).** That plan
> completes this section: it corrects the claim below that the scenario export
> is a lossy subset of the graph (each carries fields the other does not), adds
> the control/coverage fields a detection draft is actually built from, makes
> the flow map a graded rather than optional input because `technologies`,
> `authentication` and `zone` appear in no export, adds the provenance the
> exports do not yet carry, and splits normalization into a deterministic
> `normalize_paths` action that runs with no provider. Read it alongside this
> section; the node-identity rule stated here is unchanged.

Build a typed internal `DetectionNodeContext` before generation:

```text
actor_id, actor_name, application, input_hash, source_pointer
path_id, path_description, path_objective, node_index, source_event_id
component_id (nullable), asset_name, technologies, authentication, zone
technique_id, technique_name, tactic, attack_version
behavior, precondition, exploited_condition, expected_result
access_before, access_after, credential_type, credential_scope
transition, predecessors, successors, assumptions, controls_in_play
evidence, actor_support, procedure_evidence[], state_check, state_note
telemetry_requirements[], input_conflicts[], provenance_by_field
assessment: {version, tuple, details}
```

For graphs, `node_index` is the 1-based step position. For scenarios, use
validated `sequence_order` and retain `event_id`; reject duplicate sequence
numbers and report missing ordering. Preserve textual transition/state evidence
without pretending it is a structured flow. Split known scenario state prefixes
(`ok`, `gap`, `unchecked`) from the explanatory note and retain the original.

Identify a node occurrence by `(source identity, path_id, node_index)`, not by
technique or asset. Use a deterministic opaque `draft_id` derived from that key
and the format version. Record the input hash separately. Within a verified
graph/seed pair, establish an explicit common source identity; unrelated runs
with identical path names remain separate. Re-rendering saved JSON preserves
draft IDs and content. A changed path/input does not accidentally overwrite an
earlier draft. Reserve Sigma's `id` for a later rule lifecycle if required.

Scenario-only input can leave `component_id: null`. An asset name is enough to
produce a conditional design, but a guessed ID must not become a reliable join
key. Deduplicate duplicate *input wrappers* only after confirming equivalence;
never collapse T1078 occurrences across different paths.

## 4. Actor and telemetry grounding

The repository already provides `find_group`, `enrich_technique`,
`procedures_for_technique`, and `get_mitre_relationships` in
`framework/reference_data/mitre_attack.py`. Reuse these public helpers instead
of importing the projector's private prompt or validation functions.

The current projector selects one actor/software procedure per technique and
`_excerpt()` trims it to 200 characters while removing citation markers. Its
bundled procedure entries contain `source`, `technique`, and `text`, without
the original report URL. Therefore the new tool should retrieve all relevant
local procedure candidates, rank them by contextual relevance, and record their
source IDs and content hashes. A link to an ATT&CK group/technique page is an
index reference, not a recovered original report citation. If stronger report
provenance is unavailable, state that limitation.

Keep three claims separate in every draft:

- **Documented actor behavior:** the particular procedure or software evidence.
- **Modeled placement:** how the supplied path applies that behavior to this asset.
- **Detection inference:** which observable events would distinguish that behavior
  from the component's normal operation.

Explicitly call out a technique, target class, or technique-on-target procedure
that is not associated with the actor in the reviewed published evidence.
Distinguish **not established in the reviewed sources** from **atypical compared
with published behavior** and **contradicted by a source**. Absence from a
limited report set does not establish that the actor never uses a technique or
targets that class of system. Describe the reviewed source scope and the
specific departure, rather than label the whole path implausible.

Evaluate the relevant target class and behavior, not whether the actor has
attacked this particular named application. Evidence that an actor uses valid
accounts against VPNs does not automatically document its use of Kafka service
credentials. Preserve the source `actor_support: procedure_documented` in that
case while the contextual assessment can have `actor_evidence: false`.

For this actor, service/account abuse, stolen-token use, and trusted-provider
access are useful anchors. They do not establish that APT29 has attacked this
Kafka/Vault deployment. [MITRE's APT29 profile](https://attack.mitre.org/groups/G0016/)
supports the actor mappings; the supplied path provides the application placement.

APT29's use of residential proxies and token-based access makes geography or
failed-logon counts insufficient as mandatory gates. The February 2024 joint
advisory supports combining identity, session, application, and host evidence.
Here that implies monitoring what a trusted principal does after successful
authentication, including from its usual origin.
[NCSC advisory, pages 3–5](https://www.ncsc.gov.uk/files/Advisory-SVR-cyber-actors-adapt-tactics-for-initial-cloud-access.pdf)

Pin the local ATT&CK release used for generation. Preserve `Stealth` from these
exports when it agrees with that release; do not replace it with an older tactic
name from model memory. Distinguish taxonomy reconciliation from a review of
whether a technique describes the modeled behavior. Never silently relabel a
node or upgrade its evidence strength.

### Telemetry evidence rules

Maintain a small, versioned **telemetry reference library**, separate from the
future detection catalogue. It describes products, event families, native
fields, collection requirements, and documentation references, not pre-existing
detections. Begin with the products needed by this fixture.

- An event has an exact native name/ID with a reference, or an explicitly
  described event with `event_id: null` and `mapping_status: description_only`.
  Do not fabricate numeric identifiers for Kafka, PostgreSQL, Vault, or gRPC.
- Mark each source `required`, `alternative`, or `enrichment`, and separately
  record collection status as `confirmed`, `assumed`, `missing`, or `unknown`.
  A listed control is not proof that its logs contain the necessary fields.
- Separate native fields from proposed normalized fields and derived features.
  Every feature in the pseudocode must have a source, derivation, or stated gap.
- Kubernetes API audit events observe API requests. A process reading a mounted
  service-account-token file needs container/host file-access telemetry; it does
  not create a Kubernetes API audit event merely by reading that file.
  [Kubernetes auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- Vault request/response records can be paired using `request.id`; record the
  authentication method, path, operation, result, and available principal
  identifiers. Treat hashed identifiers consistently within their audit-device
  scope and do not require raw tokens or secret values in telemetry.
  [Vault audit schema](https://developer.hashicorp.com/vault/docs/audit/schema)
- PostgreSQL connection/session logs and pgAudit statement/relation events serve
  different purposes. Tenant scope and application-request correlation require
  explicit enrichment; do not assume ordinary database logs provide either.
  [PostgreSQL logging](https://www.postgresql.org/docs/18/runtime-config-logging.html),
  [pgAudit format and configuration](https://github.com/pgaudit/pgaudit)
- Kafka authorization depends on the configured authorizer. Validate whether
  successful operations and principal/resource context are logged in the deployed
  distribution; ACL existence does not prove audit coverage.
  [Kafka authorization](https://kafka.apache.org/38/security/authorization-and-acls/)

## 5. Detection record format

Use a versioned **Sigma-inspired detection draft**, not a claim of importable
Sigma. Keep familiar fields such as `title`, `status`, `description`,
`logsource`, `references`, `falsepositives`, `level`, and `tags`. Put Event Mill
extensions and pseudocode inside `x_eventmill`. Strict Sigma has specific
`detection` and `condition` semantics; pseudocode must not masquerade as a valid
Sigma condition. A later compiler can emit atomic and correlation rules.
[Sigma rules specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md)

| Field | Requirement |
|---|---|
| `title` | Begins with the source technique ID; include asset and behavior. Example: `T1078 - APT29 - Warehouse reads outside console request scope`. |
| `status` | `experimental`; this records draft maturity, not catalogue coverage. |
| `description` | Behavior being detected and its role in this path, including whether the signal observes an attempt or an outcome. |
| `logsource` | Primary product/service or descriptive source; use `definition` for required collection and uncertainty. |
| `references`, `tags` | Verified references and ATT&CK identifiers; no invented source citations. |
| `x_eventmill.format_version`, `draft_id` | Versioned local contract and deterministic node identity. |
| `x_eventmill.node` | Actor, application, path, step, component/asset, tactic, source locator, and neighboring steps. |
| `x_eventmill.grounding` | Actor evidence, placement inference, adaptation rationale, and source/mapping limitations. |
| `x_eventmill.assessment` | Versioned, expandable named tuple with `actor_evidence` and `multistep_access` booleans, plus per-element status, reason codes, basis, and source references. Required for every detection. |
| `x_eventmill.telemetry` | All sources, necessity, collection status, required fields, and configuration prerequisites. |
| `x_eventmill.events_of_interest` | Native name/ID or descriptive event; source binding and mapping status for each event. |
| `x_eventmill.detection_logic` | Kind, normalized field definitions, entity/join keys, windows, configurable thresholds, pseudocode, and missing-data behavior. |
| `x_eventmill.assumptions`, `review_flags` | Input assumptions, unresolved authentication/mapping questions, and inherited state gaps. |
| `x_eventmill.catalogue_status` | Always `new_unchecked` in v1. |
| `x_eventmill.validation_status` | `draft_unvalidated`; schema validity is not operational validation. |
| `falsepositives`, `level` | Concrete legitimate lookalikes and initial proposed severity. |

One node may need multiple streams or alternative sensor implementations.
Keep them in one node draft with named branches. Declare each branch's telemetry
requirements and whether it detects the behavior directly or a downstream proxy.
An absent enrichment source should lower confidence, not disable a viable base
detection. Missing required data must produce `insufficient_telemetry`, never
silently evaluate as a benign event or turn null into a match.

Correlation windows and anomaly thresholds are starting parameters, labeled as
proposed and tunable. Do not invent a universal numerical definition of normal
for service accounts. Where a baseline is needed, define the grouping, learning
period, minimum samples, and cold-start behavior. Prefer approved workload policy
and trace context when these are available.

### Expandable assessment tuple

Serialize the tuple as a **named YAML/JSON mapping**, not an anonymous positional
array or a language-specific tuple tag. Its initial elements are:

| Element | `true` | `false` | Warning condition |
|---|---|---|---|
| `actor_evidence` | Reviewed published evidence supports the named actor using this technique with a comparable procedure and target class. Preserve whether support is direct or via associated software. | That contextual support has not been established: the technique, target class, or procedure is unsupported, atypical, conflicting, or insufficiently evidenced. | `false` |
| `multistep_access` | Access depends on an unresolved, assumed, or omitted intermediate action/credential transition, an inherited access gap, or prerequisites that cannot be assessed. | The stated predecessors and explicit preconditions supply the access required by this node, with no additional unresolved access step identified. | `true` |

`multistep_access` encodes **unresolved access dependencies**, not merely that
the attack path contains several steps or the detection correlates several
events. Its `false` value is conditional on the modeled preconditions; it is
not proof of feasibility. Unresolved credential type, scope or acquisition can
warrant `true` even when the source's coarse `state_check` says `ok`. The two
existing `pipeline-to-vault` state gaps must produce `true` and preserve their
original explanations. A generated assessment cannot silently clear them.

Use this structure inside `x_eventmill` for every detection:

```yaml
assessment:
    version: '1.0'
    tuple:
        actor_evidence: false
        multistep_access: true
    details:
        actor_evidence:
            status: assessed
            reason_codes: [actor_target_not_established, actor_procedure_adapted]
            basis: 'Reviewed evidence concerns VPN accounts; this node applies it to Kafka.'
            source_refs: ['node.procedure_excerpt', 'grounding.limitation']
        multistep_access:
            status: assessed
            reason_codes: [credential_acquisition_not_shown]
            basis: 'A partner API key does not itself supply the separate Kafka SCRAM credential.'
            source_refs: ['node.precondition', 'node.assumptions', 'predecessor.result']
```

The example above is the Kafka T1078 node. These reference names illustrate
links into the retained context packet; production records must resolve each
reference to a source artifact/pointer or an identified evidence record.
Reasons accompany both warning and non-warning values. Use stable codes such
as `actor_technique_not_established`, `actor_target_not_established`,
`actor_behavior_atypical`, `actor_procedure_adapted`, `actor_evidence_conflict`,
`access_state_gap`, `credential_acquisition_not_shown`,
`access_prerequisite_unresolved`, and `access_continuity_supported`.
Only emit `actor_behavior_atypical` when the reviewed evidence supports that
comparison; absence of supporting evidence uses a `not_established` code.

Each element's details have `status: assessed | insufficient_evidence |
not_assessed`. Keep tuple values strictly boolean. Where assessment cannot be
completed, use the conservative value (`actor_evidence: false` or
`multistep_access: true`) with the relevant status and reason; it must not look
like an affirmative finding. Consumers must read status before styling a node.
Missing elements in an older artifact are **unassessed**, never silently
defaulted to the non-warning value. The prose and details retain the uncertainty.

Version the tuple contract independently of the detection format. New elements
can be added by name in a minor version, with a declared type, meaning, warning
polarity and details contract. Consumers preserve unknown elements and interpret
only those they support. Changing an existing element's meaning or polarity
requires a major version. An unsupported major version produces an unassessed
display rather than guessing. No positional ordering or packed bitmask is part
of the artifact contract.

### Downstream diagram styling

A Mermaid renderer can derive display classes from the tuple without storing
colors as evidence. A proposed default, after checking both element statuses:

| `actor_evidence` | `multistep_access` | Suggested class / appearance | Meaning |
|---|---|---|---|
| `true` | `false` | `assessment_supported` / neutral | Neither of these two checks raises a warning. |
| `false` | `false` | `actor_context_warning` / amber | Actor/technique/target association needs attention. |
| `true` | `true` | `access_dependency_warning` / orange | An access dependency needs attention. |
| `false` | `true` | `combined_assessment_warning` / red | Both conditions need attention. |

If either status is `insufficient_evidence` or `not_assessed`, show an
`assessment_unknown` badge/dashed outline and an explanatory label; retain any
known warning badge for the other element. Text labels/tooltips must carry the
reason codes and explanation so color is not the only signal. These classes
describe evidence/access assumptions, not detection severity, likelihood,
observed compromise, or effective monitoring coverage. Other review flags
remain visible even when this tuple is `(true, false)`.

A renderer assigns a unique diagram node ID from the node occurrence key and
maintains a mapping back to that key. It must not color every T1078 node alike,
or merge their assessments merely because the technique is shared. Actual
Mermaid renderer changes remain downstream work; this plan adds the output
contract those utilities can consume.

For the reviewed example, the Kafka T1078 node illustrates `(false, true)`:
its published actor procedure concerns a different target, and acquiring the
SCRAM credential is unresolved. Both recorded pipeline access gaps independently
require `multistep_access: true`. The warehouse T1078 example below also uses
`(false, true)` because its predecessor leaves the database credential type and
its relation to the claimed OIDC token unresolved. Preserve its original
`state_check: ok`; the additional warning explains what that coarse check did
not establish. These are assessments of the supplied evidence and assumptions,
not changes to the attack sequence.

## 6. Detection outlines for all 15 nodes

These are design targets derived from the supplied paths, not tested rules.
Products and event descriptions remain conditional on deployment confirmation.
The Kafka, Kubernetes, Vault, and PostgreSQL designs adapt the actor's identity
and token behaviors to the modeled estate; they are not claims of documented
APT29 procedures on those products. Every row becomes its own YAML section.
Every resulting detection carries the assessment tuple defined above, including
nodes with no warning from either element; prose findings are retained as well.

### partner-key-to-vault

| Step / proposed title | Required telemetry and events of interest | Detection pseudocode and context |
|---|---|---|
| 1 — `T1199 - APT29 - Partner key used outside integration scope` | gRPC/API access and authorization records: successful key authentication, method call, partner/key identifier, target tenant, result, request ID; key ownership and integration scope inventory. | `IF authenticated partner key performs an operation or tenant access outside its approved integration scope THEN alert; increase confidence for changed session/client behavior.` Include slow successful requests; partial rate limiting is not the gate. Log a key identifier, never the key. |
| 2 — `T1078 - APT29 - Kafka ingest identity used beyond producer duties` | Broker authentication/authorization or equivalent broker audit plus client tracing: successful SASL use, allowed read/write operation, topic/group, principal, client/workload identity; approved principal duties. | `IF the ingest principal performs a successful consume/read or topic access outside its approved duties THEN alert; correlate with partner activity if identity mapping exists.` Works from the expected ingest source. A long session alone is insufficient. |
| 3 — `T1021.007 - APT29 - Message consumer spawns unexpected execution` | Consumer trace with topic/partition/offset or propagated message ID; container process execution with pod/process ancestry; optional Kubernetes API audit for separate remote-exec activity. | `IF message handling is linked to unexpected child execution or executable creation in its consumer pod THEN alert.` Use temporal proximity only as weaker evidence when trace linkage is absent. Flag technique fit; a Kafka message is not a cloud login. |
| 4 — `T1528 - APT29 - Unexpected process reads pod application token` | Container runtime/host file-access telemetry: read of a configured projected token path, process/executable ancestry, pod UID, service account; optional subsequent Vault login records. | `IF a process outside the approved token-reader lineage reads a projected token THEN alert; raise confidence for later token use outside the pod's identity policy.` Normal SDK/sidecar reads are expected. API audit alone leaves the file-read branch unavailable. |
| 5 — `T1078.004 - APT29 - Vault workload identity accesses unusual secrets` | Vault audit: authentication request/result at the configured mount, secret `read`/`list`, renewal, principal/policy and workload mapping; permitted secret paths. | `IF a workload identity accesses secret paths outside its expected workload scope OR is reused from a conflicting workload THEN alert.` Join login to use where identifiers permit. Flag Cloud Accounts applicability and confirm whether auth is Kubernetes JWT, certificate, or another method. |

### pipeline-to-vault

| Step / proposed title | Required telemetry and events of interest | Detection pseudocode and context |
|---|---|---|
| 1 — `T1078.004 - APT29 - Reused SSO session accesses pipeline repository` | Identity-provider authentication/session events and source-control access audit: successful login/session use, subject/session identifiers, device/client attributes, repository actions. Product event names depend on the actual IdP/SCM. | `IF an established session is reused with conflicting device/client evidence AND accesses a pipeline-bearing repository THEN alert.` Dormant-account activation is an alternative condition when sourced. Do not require a new country or failed authentication; carry the assumed session theft. |
| 2 — `T1195.002 - APT29 - Unreviewed workflow change reaches build runner` | Repository push/merge metadata plus file diff, branch/review policy at change time, workflow dispatch/run metadata, commit SHA and runner group. Audit logs alone may lack the changed file content. | `IF a workflow/dependency change adds unapproved executable content or changes a dependency trust boundary AND the same commit is dispatched outside required approval THEN alert.` Preserve SUNSPOT software association; workflow changes alone do not prove downstream software supply-chain compromise. |
| 3 — `T1059.006 - APT29 - Build runner executes unapproved Python content` | Linux runner process execution (EDR/eBPF or configured audit telemetry), parent executable, script path/hash, job/run ID, repository and commit; approved workflow content. | `IF runner-launched Python executes content not attributable to the approved job/commit OR performs an unexpected secret-access action THEN alert.` Python is common in CI; executable name alone is insufficient. Preserve the source path's access-state gap. |
| 4 — `T1105 - APT29 - Runner stages tooling outside approved dependencies` | Runner process, outbound connection/proxy/DNS, file creation and subsequent execution; job/run/commit metadata and approved package sources. | `IF a job-linked process retrieves content outside the approved dependency manifest/source policy AND writes or executes a new tool THEN alert.` A familiar hosting domain does not prove legitimacy. Exclude verified build dependencies by identity and job context, not broad domain alone. |
| 5 — `T1528 - APT29 - Build runner retrieves unexpected Vault credentials` | Vault authentication/secret audit, runner process/network telemetry, job-to-secret allowlist; events describing attempted/successful access to relevant secret paths. | `IF runner identity/process accesses production or out-of-job-scope credential paths THEN alert; report attempts separately from successful reads.` Mark token-theft classification and unauthenticated secret access as unresolved. Preserve the state gap; no claim that HTTP reachability alone grants access. |

### console-to-warehouse

| Step / proposed title | Required telemetry and events of interest | Detection pseudocode and context |
|---|---|---|
| 1 — `T1595.002 - APT29 - Low-rate probing across console endpoints` | Load-balancer/reverse-proxy and application access logs, optionally WAF: request time, trusted client identity/address, host, route, method, response and probe indicators. | `IF repeated related requests enumerate unusual endpoint families with fingerprint/error patterns beyond the application's baseline THEN alert over both short and extended windows.` Account for shared proxies and distributed sources; do not require DDoS volume. |
| 2 — `T1190 - APT29 - Public console request triggers unexpected execution` | HTTP/gRPC request trace where applicable, Node.js application/security errors, container/host process and file telemetry; map request to workload/process. | `IF a public request is linked to unexpected command execution or executable write in the console tier THEN alert; suspicious requests without execution evidence are attempts.` Do not transplant Citrix/VPN CVE signatures into a Node.js application. |
| 3 — `T1505.003 - APT29 - Console route modified for command execution` | Container file change/integrity and process events, deployed image/release manifest, web route access, persistent-volume inventory. | `IF an unapproved file/route appears in a served executable location AND requests to it trigger unexpected execution THEN alert; file-only anomalies are a lower-confidence branch.` Confirm whether the modified location survives redeployment; retain the assumption until checked. |
| 4 — `T1528 - APT29 - Console process accesses application credential material` | Runtime file/process-access sensor for configured token/credential paths, process lineage, credential type/inventory; optional IdP or database identity-use evidence. | `IF an unexpected process reads configured application-token material THEN alert; correlate with later identity misuse.` For client-key reads label the behavior as credential access with technique review. In-process token use may be invisible to a file-read detector; make that limitation explicit. |
| 5 — `T1078 - APT29 - Warehouse reads outside console request scope` | PostgreSQL connection/session and pgAudit read records, request-to-query tracing and tenant scope, workload/service-role inventory; optional console runtime alerts. | `IF console DB identity reads data outside the linked request/approved task scope OR performs unapproved export/query behavior THEN alert even from its usual source.` A successful service login alone is not suspicious. Tenant-level detection requires tenant-aware enrichment. |

## 7. Example Markdown sections with copyable YAML

These two examples deliberately use the same technique ID with different log
sources, event semantics, and logic. They show the proposed format rather than
native Sigma rules. Filenames are illustrative; production rendering should
append a short deterministic ID if needed to prevent collisions. Normalized
field names below are a proposed contract, not assertions about native schemas.

### T1078 — partner-key-to-vault — step 2

Suggested filename: `t1078_apt29_kafka_ingest_identity_misuse.yml`

```yaml
title: 'T1078 - APT29 - Kafka ingest identity used beyond producer duties'
status: experimental
description: >-
    Detect successful Kafka operations by the partner ingest service identity
    outside its approved duties, including use from the usual application host.
logsource:
    product: kafka
    definition: >-
        Broker audit or equivalent instrumentation with successful operations,
        principal and resource context; availability and native fields unverified.
references:
    - 'https://attack.mitre.org/groups/G0016/'
    - 'https://kafka.apache.org/38/security/authorization-and-acls/'
tags:
    - attack.t1078
level: medium
falsepositives:
    - 'Approved migration temporarily gives the ingest service consumer duties.'
    - 'An integration rollout changes its permitted topics or consumer groups.'
x_eventmill:
    format_version: '1.0'
    draft_id: 'example-partner-key-to-vault-002'
    catalogue_status: new_unchecked
    validation_status: draft_unvalidated
    node:
        actor: 'APT29 (G0016)'
        application: 'Fleet Telemetry Platform'
        path_id: partner-key-to-vault
        node_index: 2
        component_id: event_bus
        tactic: Persistence
        predecessor: '1: T1199 on partner_api'
        successor: '3: T1021.007 on k8s'
        source_file: 'exports_adversary_path_projector_adversary_path_graph_20260915_165537.json'
        source_pointer: '/attack_graph/paths/0/steps/1'
    grounding:
        actor_support: procedure_documented
        documented_behavior: 'Compromised-account use against VPN infrastructure.'
        modeled_placement: 'Reuse of the ingest service SASL/SCRAM identity.'
        adaptation: 'Inspect successful principal actions beyond normal duties.'
        limitation: 'The cited actor procedure does not document Kafka abuse.'
    assessment:
        version: '1.0'
        tuple:
            actor_evidence: false
            multistep_access: true
        details:
            actor_evidence:
                status: assessed
                reason_codes: [actor_target_not_established, actor_procedure_adapted]
                basis: 'The reviewed actor evidence describes VPN access, not Kafka service-account use.'
                source_refs:
                    - 'exports_adversary_path_projector_adversary_path_graph_20260915_165537.json#/attack_graph/paths/0/steps/1/procedure_excerpt'
            multistep_access:
                status: assessed
                reason_codes: [credential_acquisition_not_shown]
                basis: 'Obtaining the separate ingest SCRAM credential is assumed, not supplied by partner-key authentication.'
                source_refs:
                    - 'exports_adversary_path_projector_adversary_path_graph_20260915_165537.json#/attack_graph/paths/0/steps/1/assumptions'
    telemetry:
        - source: kafka_operation_audit
          necessity: required
          collection_status: unknown
          required_fields: [time, cluster, principal, operation, resource, result]
          enrichment_fields: [client_id, source_workload, consumer_group]
        - source: approved_principal_duties
          necessity: required
          collection_status: unknown
          required_fields: [cluster, principal, operation, resource, validity_period]
        - source: workload_identity_mapping
          necessity: enrichment
          collection_status: unknown
          required_fields: [client_id, source_workload, principal]
    events_of_interest:
        - source: kafka_operation_audit
          event_id: null
          mapping_status: description_only
          description: 'Successful authenticated read/write operation on a topic or group.'
    detection_logic:
        kind: event_with_policy_lookup
        field_mapping_status: requires_product_validation
        entity_keys: [cluster, principal]
        parameters:
            ingest_principals: 'Required inventory of the partner API service identities.'
            allowed_duties: 'Approved principal-operation-resource tuples at event time.'
        pseudocode: |
            FOR EACH successful broker operation:
                REQUIRE the normalized principal, operation and resource
                IF principal is a known partner ingest service identity:
                    LOOK UP its approved duties valid at the event time
                    IF the operation-resource tuple is outside those duties:
                        EMIT suspicious service-account use
                        INCLUDE actual source/client/group where available
            Enrich with related partner activity only when a reliable join exists.
            Do not suppress merely because the source is the expected API host.
        missing_data: >-
            Missing operation audit or duty inventory means insufficient_telemetry.
            Missing optional client/workload enrichment reduces context only.
    assumptions:
        - 'The actor can acquire the separate ingest service SCRAM credential.'
        - 'Permitted broker ACLs are broader than the approved business duties.'
    review_flags:
        - 'Validate successful-operation auditing and native field mapping.'
        - 'Normal-duty policy must be explicit; do not equate ACL allowance with safety.'
```

---

### T1078 — console-to-warehouse — step 5

Suggested filename: `t1078_apt29_warehouse_reads_outside_console_scope.yml`

```yaml
title: 'T1078 - APT29 - Warehouse reads outside console request scope'
status: experimental
description: >-
    Detect use of the console database identity for reads outside the associated
    tenant request or approved background task, including from the allowed host.
logsource:
    product: postgresql
    definition: >-
        Connection/session logs and pgAudit read records, enriched with
        application request, tenant and approved background-task context.
references:
    - 'https://attack.mitre.org/groups/G0016/'
    - 'https://www.postgresql.org/docs/18/runtime-config-logging.html'
    - 'https://github.com/pgaudit/pgaudit'
tags:
    - attack.t1078
level: high
falsepositives:
    - 'Approved support, analytics or migration tasks spanning several tenants.'
    - 'Stale request-to-query mappings caused by connection pooling.'
x_eventmill:
    format_version: '1.0'
    draft_id: 'example-console-to-warehouse-005'
    catalogue_status: new_unchecked
    validation_status: draft_unvalidated
    node:
        actor: 'APT29 (G0016)'
        application: 'Fleet Telemetry Platform'
        path_id: console-to-warehouse
        node_index: 5
        component_id: telemetry_db
        tactic: Stealth
        predecessor: '4: T1528 on web_console'
        successor: null
        source_file: 'exports_adversary_path_projector_adversary_path_graph_20260915_165537.json'
        source_pointer: '/attack_graph/paths/2/steps/4'
    grounding:
        actor_support: procedure_documented
        documented_behavior: 'Compromised-account use against VPN infrastructure.'
        modeled_placement: 'Use of the console database identity from the console tier.'
        adaptation: 'Inspect query purpose and tenant scope after successful authentication.'
        limitation: 'This is a PostgreSQL adaptation, not a documented APT29 database procedure.'
    assessment:
        version: '1.0'
        tuple:
            actor_evidence: false
            multistep_access: true
        details:
            actor_evidence:
                status: assessed
                reason_codes: [actor_target_not_established, actor_procedure_adapted]
                basis: 'The reviewed actor evidence describes VPN access, not PostgreSQL identity misuse.'
                source_refs:
                    - 'exports_adversary_path_projector_adversary_path_graph_20260915_165537.json#/attack_graph/paths/2/steps/4/procedure_excerpt'
            multistep_access:
                status: assessed
                reason_codes: [access_prerequisite_unresolved]
                basis: 'The previous node mixes OIDC tokens and client keys; their sufficiency for database authentication is unresolved despite state_check ok.'
                source_refs:
                    - 'exports_adversary_path_projector_adversary_path_graph_20260915_165537.json#/attack_graph/paths/2/steps/3/rationale'
                    - 'exports_adversary_path_projector_adversary_path_graph_20260915_165537.json#/attack_graph/paths/2/steps/4/precondition'
    telemetry:
        - source: postgres_session_and_query_audit
          necessity: required
          collection_status: unknown
          required_fields: [time, database, db_role, session_id, statement_id, operation]
          enrichment_fields: [source_address, relation, query_fingerprint]
        - source: application_query_context
          necessity: required
          collection_status: unknown
          required_fields: [database, session_id, statement_id, request_or_job_id, permitted_scope, observed_scope, approved_operations]
          definition: >-
              Application instrumentation binds each statement to its request or
              approved task and derives scope without logging secret values.
              This is not a native pgAudit tenant field. Pool reuse must be handled.
        - source: console_runtime_alerts
          necessity: enrichment
          collection_status: unknown
          required_fields: [time, workload_id, behavior]
    events_of_interest:
        - source: postgres_session_and_query_audit
          event_id: null
          mapping_status: native_operation_documented_field_mapping_pending
          name: 'pgAudit READ class: SELECT or COPY from a relation/query'
          description: 'Read statements attributable to a known console database role.'
        - source: postgres_session_and_query_audit
          event_id: null
          mapping_status: description_only
          description: 'Successful connection/session identity associated with a statement.'
    detection_logic:
        kind: correlated_behavior
        field_mapping_status: requires_product_validation
        join_keys: [database, session_id, statement_id]
        parameters:
            console_roles: 'Required inventory of console database identities.'
            context_join_wait: 'Proposed 5 minutes for delayed telemetry; tune locally.'
            optional_prior_activity_window: 'Proposed 30 minutes; enrichment only.'
        pseudocode: |
            FOR EACH audited READ by a known console database role:
                JOIN statement to request/task context using an explicit trace mapping
                IF context or scope cannot be established after the join wait:
                    RECORD insufficient_telemetry for this branch
                ELSE IF observed data scope exceeds the request/task permitted scope:
                    EMIT suspicious use of the console database identity
                ELSE IF COPY/export is outside the request/task's approved operations:
                    EMIT suspicious export by the console database identity
            Where a trustworthy workload mapping exists, enrich with earlier
            console credential-access or execution alerts; do not require them.
            Do not require a new source IP or a failed login before the read.
        missing_data: >-
            Do not infer cross-tenant reads from relation names alone. With only
            session logs, describe identity anomalies as a weaker alternative;
            do not claim this tenant-scope detection is operational.
    assumptions:
        - 'The role permits access beyond the current request tenant.'
        - 'Query-level request/task context can be instrumented reliably.'
        - 'An audited read shows attempted query activity, not confirmed exfiltration.'
    review_flags:
        - 'Verify database authentication and credential type; mTLS alone is not OIDC.'
        - 'Validate statement outcome and data-scope measurement before deployment.'
        - 'If actor activity exactly matches legitimate reads, these signals may not distinguish it.'
```

---

## 8. Generation and validation pipeline

1. **Load and normalize deterministically.** Validate input structure, actor,
   selected paths, order and source pointers. Produce the complete expected
   node inventory before any LLM call. Malformed input fails with a structured
   error and no invented detection content.
2. **Build evidence/context packets.** Attach actor procedures, local ATT&CK
   metadata, component information, telemetry references and input warnings.
   Assess actor/technique/target alignment and unresolved access dependencies;
   populate the versioned tuple with source-linked reasons and assessment status.
   Give every claim a source classification. Treat report/path text as data,
   not instructions that can change the output contract.
3. **Generate structured records through the existing LLM interface.** Use
   `context.llm_query.query_text` with heavy-tier reasoning and structured
   output hints. Generate JSON records; YAML/Markdown formatting is deterministic.
   Do not instantiate provider SDK clients in the plugin.
4. **Batch by path while retaining sequence context.** For this fixture,
   propose one call for each five-step path: three calls before any retries.
   Size batches against the selected provider's content budget after reasoning
   reserve, rather than hardcode a node limit as a guarantee. For long paths,
   carry a shared full-path context outline plus complete target-node packets;
   split output batches without losing predecessor/successor evidence.
5. **Validate each returned node.** Enforce source node identity, technique
   prefix, immutable provenance, required telemetry/events/logic fields,
   valid reference IDs, and allowed enum values. Cross-check that pseudocode
   inputs are declared and multi-source joins have keys. Require the tuple on
   every node, validate boolean types and per-element details, and enforce that
   inherited access gaps cannot become `multistep_access: false`. Source-derived
   facts stay immutable; contextual actor-fit judgments must expose their basis
   and remain reviewable rather than be presented as deterministic proof.
   The validator checks
   structure and declared dependencies; a human still evaluates detection quality.
6. **Repair only affected records.** Reject truncated replies even when the
   transport reports success. Permit a bounded targeted repair for missing or
   invalid nodes, recording original failure and replacement lineage. Treat
   transport retries and semantic repairs as a combined deadline/cost budget.
   If time is insufficient, persist progress and stop with explicit partial status.
7. **Check complete coverage by identity.** Set comparison, not record count,
   must establish `expected_node_keys == validated_node_keys`. Duplicate,
   unexpected or missing nodes prevent `complete` status. Do not fill a missing
   response with a generic technique rule and mark it generated.
8. **Render and persist deterministically.** Serialize with a YAML library,
   safe-load each block, validate it against the draft schema, and compare the
   parsed blocks to the JSON sidecar. Write UTF-8 files with LF endings and
   unique run IDs, using temporary files and final replacement in the artifact
   directory. Report write/registration failures explicitly.
   The Markdown coverage table, copied YAML and sidecar must agree on tuple
   values, statuses, source references and node occurrence identity.

Use distinct completion measures:

```text
generation_status: complete | partial | failed
expected_nodes: 15
generated_drafts: <count>
failed_nodes: [<node keys and reasons>]
mapping_review_nodes: [<node keys>]
telemetry_gap_nodes: [<node keys>]
validation_status: draft_unvalidated
```

`complete` means all selected nodes have valid design records, not that the
estate has detection coverage. Partial workbooks retain a clearly labeled
failure section for every missing node; those sections do not count as
detections. The tool should return `ok: false` with a specific incomplete-generation
error and available partial artifacts when any requested draft could not be
produced. Never silently claim 15 detections when fewer exist.

Record input and optional-context hashes, schema/prompt versions, ATT&CK
release, reference-library version, actual provider/vendor/model attribution,
token usage, timing and repair history in the sidecar. Re-running the model is
not guaranteed to produce identical prose; rendering the saved validated
records should be repeatable without another model call.

## 9. Repository integration and implementation stages

Proposed files:

```text
plugins/threat_modeling/attack_path_detection_designer/
    __init__.py
    manifest.json
    tool.py
    normalization.py
    grounding.py
    generation.py
    rendering.py
    schemas/input.schema.json
    schemas/output.schema.json
    schemas/detection_draft.schema.json
    reference_data/telemetry_profiles.json
    tests/test_contract.py
    tests/test_normalization.py
    tests/test_generation.py
    tests/test_rendering.py
    examples/
    README.md
```

Keep `tool.py` as orchestration. Normalization owns source adaptation;
grounding owns evidence and telemetry contracts; generation owns the prompt,
response validation and retries; rendering owns YAML/Markdown serialization.
This keeps provider transport in the framework and output layout out of prompts.

Manifest defaults: `pillar: threat_modeling`, `also_useful_in: [log_analysis]`,
`stability: experimental`, `model_tier: heavy`, `requires_llm: true`,
`timeout_class: slow`, and `safe_for_auto_invoke: false`, consistent with the
cost and analyst judgment involved. Use a bounded `summary_budget` that reports
coverage counts, unresolved issues and artifact links without pasting the
workbook into later LLM context. Register `chains_from: [adversary_path_projector]`
and add the reciprocal projector discovery entry during implementation.

Use the existing execution context, artifact registration, workspace location
and CLI `show`/`export` behavior. Declare a YAML serialization dependency in the
appropriate project/plugin packaging; it is not in the current core dependency
list. No SIEM connection, rule import, automatic deployment, existing-rule
lookup, or catalogue matching is part of v1.

| Stage | Deliverable | Acceptance gate |
|---|---|---|
| 1. Contracts and adapters | Input/output/draft schemas; normalized graph and scenario contexts; deterministic source/identity handling. | Each supplied input independently produces the same 15 ordered node occurrences, with documented differences in available context. |
| 2. Grounding and telemetry | Actor procedure selection, telemetry references, mapping warnings, versioned assessment tuple, optional context enrichment. | Exact actor evidence remains distinct from modeled placement; atypical or unsupported actor/technique/target associations and unresolved access dependencies have source-linked indicators. |
| 3. Draft generation | Provider-neutral LLM calls, batching, coverage ledger, bounded repair, partial artifacts. | One valid draft per selected node; omissions, duplicates and truncated responses cannot pass as complete. |
| 4. Workbook delivery | YAML serializer, Markdown dividers, JSON sidecar, artifact registration, CLI examples and README. | Each copied block parses independently and preserves node identity, tuple and reasons; Markdown and JSON agree, and downstream utilities can join by node occurrence. |
| 5. Analyst evaluation | Run the fixture with a configured provider and inspect all 15 outputs; then evaluate selected drafts against labeled telemetry. | Review distinguishes Kafka/DB/SSO/Vault identity contexts and records operational blind spots and false positives. |

Contract tests should exercise real failure modes:

- Graph-only, scenario-only and single-scenario adapters; repeated technique
  IDs and repeated `AE-0001` values across paths; unknown paths, duplicate
  orders and ambiguous source wrappers.
- The two existing state gaps and SUNSPOT's `via_software` support survive
  normalization, generation and rendering. `Stealth` follows the local taxonomy.
- Every detection has both tuple elements and their details. An existing
  `actor_support: procedure_documented` can coexist with `actor_evidence: false`
  when the procedure/target association is an adaptation; the former is unchanged.
- Both existing pipeline gaps force `multistep_access: true`. The Kafka credential
  acquisition assumption and the warehouse credential-type ambiguity remain
  warnings even with source `state_check: ok`. Multiple path steps or multiple
  detection streams alone do not force that value.
- All four boolean combinations have defined display interpretations. Unknown
  evidence/status and older missing fields cannot appear as an affirmative
  association or a passed access assessment; warning labels accompany color.
- Adding a tuple element does not shift existing meanings; unknown keys survive
  a round trip, unsupported major versions are handled explicitly, and repeated
  techniques join to the correct node occurrence. These are contract checks;
  implementing diagram rendering is separate downstream work.
- A response containing 15 records with one duplicated key and one omitted
  key is incomplete. Unexpected nodes and changed technique IDs are rejected.
- Missing product/version metadata produces descriptive events, not invented
  IDs. A `T1078` label cannot force Windows authentication logs onto Kafka.
- A Kubernetes file-read proposal cannot pass with only Kubernetes API audit
  declared as the necessary source. A tenant-scope query needs scope enrichment.
- Truncation, timeout, invalid structured output, failed repair, cancellation,
  and artifact-write failures retain truthful coverage accounting.
- YAML quoting, multiline pseudocode, Unicode text and input backticks cannot
  break fences or lose data; each parsed block agrees with its sidecar record.
- Positive and benign examples cover misuse from an allowed source, legitimate
  producer operations, approved CI Python/dependency downloads, and permitted
  tenant reads. Missing telemetry is distinguishable from a non-match.

Test generation with scripted LLM responses first. A live LLM run verifies
integration and draft quality, not detection effectiveness. Effectiveness
requires labeled events or controlled replay using the actual product versions,
field mappings, joins and collection settings. Record the exact validation
performed before promoting any draft.

## 10. Review status for this plan

The supplied JSON was parsed, the 3-path/15-node inventory and graph/seed
correspondence were checked, and the projector's current serialization,
procedure handling, plugin contract and ATT&CK helpers were inspected. Sigma
and the linked primary telemetry/actor references were consulted. The plan
includes a proposed detection for each node and two complete format examples.

Revision 2026-09-16: retained the path and prose findings, added explicit
actor/technique/target alignment guidance, and specified the expandable
`actor_evidence` / `multistep_access` tuple in every detection. Updated both
complete examples, downstream styling semantics and acceptance checks. This
revision changes the plan document only.

Revision 2026-09-16 (second): the normalization layer this plan depends on is
now specified separately in `docs/specs/attack_path_detection_normalization.md`,
after reviewing the second export pair (`20260915_204815`, Scattered Spider vs
Application B, 24 nodes across paths of 7/7/10 with a technique repeating three
times inside one path). Section 3 carries a pointer; the corrections that plan
asks of this one — node counts as data rather than the constant 15, the
batching rule, the graph/seed union — are listed in its section 6 and are not
yet applied here.

No plugin code or source exports were changed. No generated detection has been
tested against live telemetry, and no LLM generation run was performed. The
local Python launcher reports `No installed Pythons found!`; therefore Python
contract tests and an actual YAML-parser round trip remain implementation-time
checks rather than claimed validation of these examples.
