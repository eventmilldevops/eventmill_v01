# Attack Path Visualizer

Draws attack paths as Mermaid flowcharts, ASCII box-and-arrow chains or a
one-line flow. Deterministic, with no LLM, no network and no cost. It reads an
`adversary_path_projector` path graph, a `threat_intel_ingester` output, or
stages supplied inline.

Its job in the detection workflow is **orientation**. It shows the shape of a
projection: where paths start, where they converge, and how two projections
differ. That makes it quick to check a run, and something to show the person
who asked the question. It is **not the record**. The picture is by technique,
not by component, and it does not show which controls sit on a step. The
detection designer's JSON is the record. See *What the picture does not show*
before reading anything into colour.

## Where this sits

This is step 2 of three:

| # | Tool | Produces |
|---|---|---|
| 1 | `adversary_path_projector` | a path graph and scenario seed per projection |
| 2 | **`attack_path_visualizer`** | a picture of the path graph |
| 3 | `attack_path_detection_designer` | one detection draft per path step |

The complete walkthrough, from a leader asking *"how exposed is Application B
to Scattered Spider?"* to detection drafts compared across several models, is
in [the projector's README](../adversary_path_projector/README.md#from-a-leaders-question-to-detection-drafts).
This file covers the visualizer's part of it.

## Running it on a projection

```bash
# the path graph from adversary_path_projector — the usual case
run attack_path_visualizer --artifact_id <graph id> --format mermaid --attack_type "Scattered Spider"

# terminal-friendly: one vertical chain per path
run attack_path_visualizer --artifact_id <graph id> --format ascii --attack_type "Scattered Spider"

# both at once
run attack_path_visualizer --artifact_id <graph id> --format both --attack_type "Scattered Spider"
```

Pass the **path graph**, `adversary_path_graph_<stamp>.json`, not the scenario
seed. The seed has neither `attack_graph` nor `mitre_mappings`, so it fails
with `NO_MITRE_MAPPINGS`. The graph id is printed when the
projection finishes, and `artifacts` lists it again later.

Set `--attack_type`. It labels the diagram header, and on the artifact route it
defaults to `threat-intel`. That is misleading on a projection, and it matters
once you have several diagrams open side by side.

## Comparing projections

Projection is sampled, and the workflow deliberately runs it several times on
several models. Every projector invocation writes its own graph, so render
each one:

```bash
run attack_path_visualizer --artifact_id <gemini graph id> --format mermaid --attack_type "SS / gemini"
run attack_path_visualizer --artifact_id <anthropic graph id> --format mermaid --attack_type "SS / anthropic"
```

Read them side by side for three things:

- **Convergence points**, which are techniques reached by more than one path
  (orange). One detection at a convergence point covers several routes, if
  the paths meet on the same component. The picture cannot tell you that, so
  check the step's `component_id` in the graph JSON.
- **Entry points** (blue). Different models starting in different places is
  the first sign of an outlier.
- **A technique only one model uses.** It may be the credible path nobody has
  considered, or it may be that model's habit. The projector's
  `summarize_run_group` report is where recurrence and cross-model agreement
  are actually counted. The picture only helps you spot them.

## Reading a projector graph

The graph route builds a directed graph from `attack_graph.paths[].steps[]`
and each step's `leads_to`.

**Node identity is `(technique_id, tactic)`.** A technique used with two
different tactics renders as two nodes, which keeps the multi-role context.
The same technique with the *same* tactic renders as **one** node wherever it
occurs. That includes other paths, and other components.

In Mermaid, nodes are coloured by role:

| Colour | Role |
|---|---|
| Blue | entry point: no incoming edge; labelled with the path id(s) it starts |
| Yellow | mid-chain |
| Red | exit or terminal: no outgoing edge |
| Orange | convergence point, as listed by the projector |

Paths and their descriptions are written as `%%` comments at the top of the
`.mmd`, and as a legend under the fenced block in the `.md`.

In ASCII, each path is its own vertical chain. Shared nodes carry
`also in: <other paths>`, and tags mark `▷ ENTRY`, `■ EXIT`, `◆ CONVERGE` and
`? TACTIC`.

## What the picture does not show

This section matters more than the rest of the file. Each limitation below
could lead a reader to the wrong conclusion.

- **No components.** A projector step carries `component_id` and `asset`, and
  the renderer ignores both. Scattered Spider's `T1078` on the entry API and
  `T1078` on the Okta tenant are one box if they share a tactic. The detection
  designer treats them as two nodes needing two different detections. That is
  the reason the designer's JSON, not this picture, is the record.
- **No controls, and a false "Unprotected" line.** On the graph route, node
  controls are never filled in. The projector's `controls_in_play`, the flow
  map's controls and the designer's `monitoring_claim` are all ignored. As a
  result:
  - the Mermaid legend's green **Has Controls** colour never appears;
  - `--include_controls` has no effect (it applies only to inline stages);
  - the ASCII output ends with **`⚠ Unprotected stages:`** followed by
    **every non-exit technique**, whatever the flow map declares.
  **That line is not a finding.** For whether a control exists where a step
  lands, read the projector's summary (*"No controls declared at all on: …"*)
  or the designer's digest.
- **No state.** `state_check: gap`, `HOP_NOT_DECLARED`, assumptions and access
  states are not drawn. A path with an unexplained jump looks the same as one
  without.
- **No assessment.** The designer's `actor_evidence` / `multistep_access` tuple
  is designed so that a renderer can colour a node by it
  (`docs/specs/attack_path_detection_designer.md`, *Downstream diagram
  styling*). This renderer does not do that yet.
- **Compact on a graph lists every node in first-seen order**, across paths.
  It is a technique inventory, not a route.

Fixing the first two means reading `component_id` and the step's controls into
each node, and keying nodes by occurrence rather than by technique. The change
is additive, and the projector spec records it as deferred work
(*Deferred: rendering the component binding*). It has not been done.

## Other input routes

### From `threat_intel_ingester`

```bash
run attack_path_visualizer --artifact_id <ingester json_events id> --format mermaid
```

The ingester summary includes a ready-to-paste `Quick chart:` line. If the
artifact carries an `attack_graph` with paths, it renders as above. Otherwise
the renderer falls back to a **linear** chain built from `mitre_mappings`: it
groups techniques by tactic, orders them in kill-chain sequence, and makes the
highest-confidence technique per tactic the stage.

Ingester entries may carry `"tactic_mismatch": true` when the assigned tactic
is not one ATT&CK lists for the technique and the ingester could not correct
it. Those nodes show *tactic unconfirmed* in Mermaid and `? TACTIC` in ASCII.
The behaviour is real, and only the tactic label is in doubt. The mapping's
`allowed_tactics` lists the choices.

### Inline stages

`stages` is a list of objects, so it needs the JSON form:

```bash
run attack_path_visualizer {"format": "ascii", "attack_type": "ransomware", "stages": [{"name": "Initial Access", "mitre_technique_id": "T1566", "stage_present": true, "controls": [{"control_name": "Mail gateway", "control_type": "preventive", "effectiveness_rating": "moderate"}], "gaps_detected": []}]}
```

This is the one route where **controls and gaps are drawn**. It shows
effectiveness bars in ASCII, and in Mermaid green for a stage with controls,
yellow for one without, red for one with gaps, plus a coverage matrix unless
`--include_controls false`.

## Arguments

| Argument | Required | Default | Notes |
|---|---|---|---|
| `artifact_id` | one of `artifact_id` / `stages` | — | a `json_events` artifact registered in this session |
| `stages` | one of `artifact_id` / `stages` | — | inline stages (see schema) |
| `format` | no | `ascii` | `ascii`, `mermaid`, `compact`, `both` |
| `attack_type` | no | `unknown`, or `threat-intel` on the artifact route | the header label |
| `attack_narrative` | no | — | inline stages, ASCII only |
| `include_controls` | no | `true` | the Mermaid coverage matrix, inline stages only |

## What a run leaves behind

The shell prints three things: the **summary** (which also goes into the LLM
context, so it never contains the drawing), the **full rendering**, and the
**files** with their artifact ids. `show <artifact_id>` prints a file again.

On the graph route the tool writes its own files to
`$EVENTMILL_WORKSPACE/artifacts/` and registers them as `text`:

| Format | Files |
|---|---|
| `mermaid` | `attack_path_mermaid_<ts>.mmd` (raw Mermaid, for Mermaid CLI, VS Code or mermaid.live) and `attack_path_mermaid_<ts>.md` (fenced, with the path legend, for GitHub or VS Code preview) |
| `ascii` | `attack_path_ascii_<ts>.txt` |
| `compact` | `attack_path_compact_<ts>.txt` |
| `both` | the ASCII `.txt` plus both Mermaid files |

On the linear and inline routes the tool writes nothing itself. The shell
saves the rendering as `attack_path_visualizer_<ts>.md`.

### On Cloud Run

`workspace/artifacts` in the container is ephemeral. This tool is the one
exported to the common bucket **by default** after each run, under
`exports/attack_path_visualizer/`, and the shell prints the `gs://` URIs. The
projector's and designer's outputs are not exported by default. Use
`export --all <subfolder>` before closing the session, or set
`EVENTMILL_AUTO_EXPORT_TOOLS` (`*` for all, empty to disable).
`EVENTMILL_AUTO_EXPORT=1` enables it outside Cloud Run.

## Notes

- `safe_for_auto_invoke: true`. It renders only, and costs nothing.
- The projector and the ingester reach it by artifact id. The manifest also
  names `threat_model_analyzer` and `risk_assessment_analyzer` in
  `chains_from`. Their outputs carry no `attack_graph` or `mitre_mappings`, so
  they reach it only as inline `stages`.
- `help attack_path_visualizer` in the shell shows the argument syntax.
