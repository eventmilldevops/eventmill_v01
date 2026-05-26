"""
Attack Path Visualizer — Generate ASCII art, Mermaid diagrams, and compact flow visualizations.

Ported from Event Mill v1.0 visualization.py with improvements:
- Conforms to EventMillToolProtocol
- Structured JSON output wrapping visualization text
- Multiple output formats: ascii, mermaid, compact, both
- Control coverage matrix rendering
- summarize_for_llm() for context-optimized output
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# MITRE ATT&CK tactic → kill-chain stage mapping
# ---------------------------------------------------------------------------

TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

TACTIC_DISPLAY = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

_CONF_RANK = {"high": 2, "medium": 1, "low": 0}


def _build_stages_from_threat_intel(data: dict) -> list[dict]:
    """Convert threat_intel_ingester json_events output into attack_path_visualizer stages.

    Groups MITRE technique mappings by tactic and orders them in kill-chain
    sequence.  The highest-confidence technique per tactic becomes the primary
    stage entry; additional techniques are recorded as metadata.
    """
    mitre_mappings = data.get("mitre_mappings", [])
    if not mitre_mappings:
        return []

    # Group by normalised tactic label
    buckets: dict[str, list[dict]] = {}
    for mapping in mitre_mappings:
        tactic = mapping.get("tactic", "unknown").lower().replace(" ", "-")
        buckets.setdefault(tactic, []).append(mapping)

    stages: list[dict] = []

    # Known tactics in kill-chain order
    for tactic in TACTIC_ORDER:
        if tactic not in buckets:
            continue
        techniques = sorted(
            buckets[tactic],
            key=lambda t: _CONF_RANK.get(t.get("confidence", "low"), 0),
            reverse=True,
        )
        primary = techniques[0]
        extra_ids = [t.get("technique_id", "") for t in techniques[1:] if t.get("technique_id")]
        stage: dict[str, Any] = {
            "name": TACTIC_DISPLAY.get(tactic, tactic.replace("-", " ").title()),
            "mitre_technique_id": primary.get("technique_id", ""),
            "technique_claimed": primary.get("technique_name", ""),
            "stage_present": True,
            "controls": [],
            "gaps_detected": [],
        }
        if extra_ids:
            stage["additional_techniques"] = extra_ids
        stages.append(stage)

    # Unknown / ICS-only tactics appended at end
    for tactic, techniques in buckets.items():
        if tactic in TACTIC_ORDER:
            continue
        primary = sorted(
            techniques,
            key=lambda t: _CONF_RANK.get(t.get("confidence", "low"), 0),
            reverse=True,
        )[0]
        stages.append({
            "name": tactic.replace("-", " ").title(),
            "mitre_technique_id": primary.get("technique_id", ""),
            "technique_claimed": primary.get("technique_name", ""),
            "stage_present": True,
            "controls": [],
            "gaps_detected": [],
        })

    return stages


# ---------------------------------------------------------------------------
# DAG data model
# ---------------------------------------------------------------------------

@dataclass
class DAGNode:
    """A node in the attack path DAG."""
    technique_id: str
    technique_name: str
    tactic: str
    leads_to: list[str]       # composite keys of downstream nodes
    controls: list[dict]
    gaps_detected: list[str]
    path_ids: list[str]       # which paths this node appears in


@dataclass
class AttackDAG:
    """Directed acyclic graph of attack paths."""
    nodes: dict[str, DAGNode]  # keyed by composite "tid|tactic-slug"
    paths: list[dict]           # original path metadata
    convergence_points: list[str]
    branch_points: list[str]
    entry_points: list[str]    # nodes with no incoming edges
    exit_points: list[str]     # nodes with no outgoing edges


def _node_key(tid: str, tactic: str) -> str:
    """Build a composite node key from technique ID and tactic.

    Nodes for the same technique with different tactics become distinct
    nodes in the DAG, preserving multi-role visibility.
    """
    slug = tactic.lower().replace(" ", "-") if tactic else "unknown"
    return f"{tid}|{slug}"


def _build_dag_from_attack_graph(
    attack_graph: dict,
    mitre_mappings: list[dict],
) -> "AttackDAG | None":
    """Build a DAG from the LLM-produced attack_graph structure.

    Nodes are keyed by ``(technique_id, tactic)`` so the same technique
    serving different tactical roles in different paths renders as
    separate nodes.  Edges are resolved within per-path context so that
    ``leads_to`` targets point to the correct tactic-specific node.

    Returns None if the attack_graph is empty or has no paths,
    signaling the caller to fall back to the legacy linear builder.
    """
    paths = attack_graph.get("paths", [])
    if not paths:
        return None

    # Build a lookup for technique metadata from mitre_mappings,
    # keyed by (technique_id, tactic) with fallback by technique_id alone.
    info_by_pair: dict[tuple[str, str], dict] = {}
    info_by_tid: dict[str, dict] = {}
    for m in mitre_mappings:
        tid = m.get("technique_id", "")
        tactic = m.get("tactic", "")
        if tid:
            info_by_pair[(tid, tactic)] = {
                "technique_name": m.get("technique_name", ""),
                "tactic": tactic,
            }
            if tid not in info_by_tid:
                info_by_tid[tid] = {
                    "technique_name": m.get("technique_name", ""),
                    "tactic": tactic,
                }

    # First pass: build per-path step mapping (technique_id -> tactic)
    path_step_map: dict[str, dict[str, str]] = {}
    for path in paths:
        pid = path.get("path_id", "unknown")
        path_step_map[pid] = {}
        for step in path.get("steps", []):
            tid = step.get("technique_id", "")
            tactic = step.get("tactic", "")
            if tid:
                path_step_map[pid][tid] = tactic

    def _resolve_target_key(target_tid: str, source_path_id: str) -> str:
        """Resolve a leads_to target to its composite node key.

        Look up the target's tactic within the same path first, then
        fall back to other paths, then to metadata lookup.
        """
        tactic = path_step_map.get(source_path_id, {}).get(target_tid, "")
        if not tactic:
            for pid, pmap in path_step_map.items():
                if target_tid in pmap:
                    tactic = pmap[target_tid]
                    break
        if not tactic:
            info = info_by_tid.get(target_tid, {})
            tactic = info.get("tactic", "")
        return _node_key(target_tid, tactic)

    # Second pass: create nodes and edges
    nodes: dict[str, DAGNode] = {}
    all_target_keys: set[str] = set()

    for path in paths:
        path_id = path.get("path_id", "unknown")
        for step in path.get("steps", []):
            tid = step.get("technique_id", "")
            step_tactic = step.get("tactic", "")
            if not tid:
                continue

            nk = _node_key(tid, step_tactic)

            if nk not in nodes:
                info = info_by_pair.get(
                    (tid, step_tactic),
                    info_by_tid.get(tid, {}),
                )
                nodes[nk] = DAGNode(
                    technique_id=tid,
                    technique_name=(
                        info.get("technique_name", "")
                        or step.get("technique_name", "")
                    ),
                    tactic=step_tactic or info.get("tactic", ""),
                    leads_to=[],
                    controls=[],
                    gaps_detected=[],
                    path_ids=[],
                )

            # Resolve leads_to to composite keys within path context
            for target_tid in step.get("leads_to", []):
                if not target_tid:
                    continue
                target_nk = _resolve_target_key(target_tid, path_id)
                all_target_keys.add(target_nk)
                if target_nk not in nodes[nk].leads_to:
                    nodes[nk].leads_to.append(target_nk)

            if path_id not in nodes[nk].path_ids:
                nodes[nk].path_ids.append(path_id)

    # Ensure target nodes exist even if they weren't listed as steps
    for target_key in all_target_keys:
        if target_key not in nodes:
            # Parse tid from composite key (tid|tactic-slug)
            parts = target_key.split("|", 1)
            tid = parts[0]
            info = info_by_tid.get(tid, {})
            nodes[target_key] = DAGNode(
                technique_id=tid,
                technique_name=info.get("technique_name", ""),
                tactic=info.get("tactic", ""),
                leads_to=[],
                controls=[],
                gaps_detected=[],
                path_ids=[],
            )

    if not nodes:
        return None

    # Identify entry and exit points (using composite keys)
    entry_points = [nk for nk in nodes if nk not in all_target_keys]
    exit_points = [nk for nk in nodes if not nodes[nk].leads_to]

    return AttackDAG(
        nodes=nodes,
        paths=paths,
        convergence_points=attack_graph.get("convergence_points", []),
        branch_points=attack_graph.get("branch_points", []),
        entry_points=entry_points,
        exit_points=exit_points,
    )


# ---------------------------------------------------------------------------
# Protocol-compatible result types
# ---------------------------------------------------------------------------

@dataclass
class ToolResult:
    ok: bool
    result: dict[str, Any] | None = None
    error_code: str | None = None
    message: str | None = None
    output_artifacts: list[str] | None = None
    details: dict[str, Any] | None = None


@dataclass
class ValidationResult:
    ok: bool
    errors: list[str] | None = None


# ---------------------------------------------------------------------------
# Text helpers
# ---------------------------------------------------------------------------

def _wrap_text(text: str, width: int) -> list[str]:
    """Wrap text to specified width."""
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        if len(current) + len(word) + 1 <= width:
            current += (" " if current else "") + word
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines


EFF_BAR = {"strong": "███", "moderate": "██░", "weak": "█░░", "nominal": "░░░"}


# ---------------------------------------------------------------------------
# ASCII Rendering
# ---------------------------------------------------------------------------

def _render_ascii(stages: list[dict], attack_type: str, narrative: str) -> str:
    """Render detailed ASCII box-and-arrow attack path."""
    present = [s for s in stages if s.get("stage_present", True)]
    missing_req = [s for s in stages if not s.get("stage_present", True) and s.get("relevance") == "required"]

    if not present and not missing_req:
        return "No attack stages provided."

    box_width = 100
    lines: list[str] = []

    # Header
    lines.append("")
    header_w = box_width + 4
    lines.append("+" + "=" * header_w + "+")
    lines.append("|" + f" ATTACK PATH - {attack_type.upper()} ".center(header_w) + "|")
    lines.append("+" + "=" * header_w + "+")
    lines.append("")

    if narrative:
        for ln in _wrap_text(narrative, box_width)[:4]:
            lines.append(f"  {ln}")
        lines.append("")

    # Detailed stage boxes
    for i, stage in enumerate(present):
        name = stage.get("name", "Unknown")
        technique = stage.get("technique_claimed", "")
        mitre_id = stage.get("mitre_technique_id", "")
        controls = stage.get("controls", [])
        gaps = stage.get("gaps_detected", [])

        lines.append("  +" + "-" * box_width + "+")

        header = f" {i + 1}. {name}"
        if mitre_id:
            header += f" ({mitre_id})"
        lines.append("  |" + header.ljust(box_width) + "|")

        if technique:
            for j, tl in enumerate(_wrap_text(technique, box_width - 16)[:2]):
                prefix = "    Technique: " if j == 0 else "               "
                lines.append("  |" + (prefix + tl).ljust(box_width) + "|")

        if controls:
            lines.append("  |" + "    Controls:".ljust(box_width) + "|")
            for ctrl in controls[:4]:
                cn = ctrl.get("control_name", "?")
                ct = ctrl.get("control_type", "?")[0].upper()
                eff = EFF_BAR.get(ctrl.get("effectiveness_rating", ""), "???")
                max_name = box_width - 20
                if len(cn) > max_name:
                    cn = cn[: max_name - 3] + "..."
                cl = f"      [{ct}] {cn} {eff}"
                lines.append("  |" + cl.ljust(box_width) + "|")
            if len(controls) > 4:
                lines.append("  |" + f"      ... +{len(controls) - 4} more".ljust(box_width) + "|")

        if gaps:
            lines.append("  |" + "    Gaps:".ljust(box_width) + "|")
            for gap in gaps[:3]:
                for j, gl in enumerate(_wrap_text(gap, box_width - 10)[:2]):
                    prefix = "      - " if j == 0 else "        "
                    lines.append("  |" + (prefix + gl).ljust(box_width) + "|")

        lines.append("  +" + "-" * box_width + "+")

        if i < len(present) - 1:
            lines.append("           |")
            lines.append("           V")

    if missing_req:
        lines.append("")
        lines.append("  MISSING REQUIRED STAGES:")
        for s in missing_req:
            lines.append(f"      X {s.get('name', 'Unknown')}")

    lines.append("")
    lines.append("  " + "-" * (box_width + 2))
    lines.append("  Legend: ### strong | ##. moderate | #.. weak | ... nominal")
    lines.append("          [P] preventive | [D] detective | [R] responsive")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Compact Rendering
# ---------------------------------------------------------------------------

def _render_compact(stages: list[dict], attack_type: str) -> str:
    """Render compact single-line flow."""
    present = [s for s in stages if s.get("stage_present", True)]
    if not present:
        return "No attack stages to visualize."

    boxes = []
    for s in present:
        name = s.get("name", "?")
        if len(name) > 15:
            name = name[:12] + "..."
        boxes.append(name)

    flow = "  " + " --> ".join(f"[{b}]" for b in boxes)

    total_controls = sum(len(s.get("controls", [])) for s in present)
    total_gaps = sum(len(s.get("gaps_detected", [])) for s in present)

    lines = [
        f"\n  {attack_type.upper()} ATTACK PATH:",
        "",
        flow,
        "",
        f"  Stages: {len(present)} | Controls: {total_controls} | Gaps: {total_gaps}",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Mermaid Rendering
# ---------------------------------------------------------------------------

def _render_mermaid(stages: list[dict], attack_type: str, include_controls: bool) -> str:
    """Render Mermaid flowchart diagram."""
    present = [s for s in stages if s.get("stage_present", True)]
    if not present:
        return "```mermaid\nflowchart TB\n    A[No stages found]\n```"

    lines = [
        "```mermaid",
        "flowchart TB",
        f'    subgraph attack["{attack_type.upper()} Attack Path"]',
        "    direction TB",
    ]

    for i, stage in enumerate(present):
        name = stage.get("name", "Unknown")
        mitre_id = stage.get("mitre_technique_id", "")
        controls = stage.get("controls", [])
        gaps = stage.get("gaps_detected", [])
        nid = f"S{i}"

        label = name
        if mitre_id:
            label += f"<br/><small>{mitre_id}</small>"

        if gaps:
            label += f"<br/><small>! {len(gaps)} gap(s)</small>"
            lines.append(f'    {nid}[["{label}"]]')
        elif controls:
            label += f"<br/><small>{len(controls)} control(s)</small>"
            lines.append(f'    {nid}["{label}"]')
        else:
            lines.append(f'    {nid}(["{label}"])')

    for i in range(len(present) - 1):
        lines.append(f"    S{i} --> S{i + 1}")

    lines.append("    end")
    lines.append("")
    lines.append("    %% Styling")

    for i, stage in enumerate(present):
        gaps = stage.get("gaps_detected", [])
        controls = stage.get("controls", [])
        if gaps:
            lines.append(f"    style S{i} fill:#ffcccc,stroke:#cc0000")
        elif not controls:
            lines.append(f"    style S{i} fill:#ffffcc,stroke:#cccc00")
        else:
            lines.append(f"    style S{i} fill:#ccffcc,stroke:#00cc00")

    lines.append("```")

    if include_controls:
        lines.append("")
        lines.append(_render_mermaid_control_matrix(present))

    return "\n".join(lines)


def _render_mermaid_control_matrix(stages: list[dict]) -> str:
    """Render control coverage matrix as Mermaid."""
    all_controls: dict[str, dict] = {}
    for stage in stages:
        for ctrl in stage.get("controls", []):
            cn = ctrl.get("control_name", "Unknown")
            if cn not in all_controls:
                all_controls[cn] = {
                    "effectiveness": ctrl.get("effectiveness_rating", "unknown"),
                    "stages": [],
                }
            all_controls[cn]["stages"].append(stage.get("name", "?"))

    if not all_controls:
        return ""

    lines = [
        "```mermaid",
        "flowchart LR",
        '    subgraph controls["Control Coverage Matrix"]',
    ]

    for i, (cn, info) in enumerate(all_controls.items()):
        eff = info["effectiveness"]
        sc = len(info["stages"])
        label = f"{cn[:25]}<br/><small>{eff} | {sc} stage(s)</small>"
        lines.append(f'    C{i}["{label}"]')

    lines.append("    end")
    lines.append("")

    eff_colors = {
        "strong": "fill:#00cc00,color:#fff",
        "moderate": "fill:#cccc00",
        "weak": "fill:#ff9900",
        "nominal": "fill:#cc0000,color:#fff",
    }
    for i, (_, info) in enumerate(all_controls.items()):
        style = eff_colors.get(info["effectiveness"], "fill:#999")
        lines.append(f"    style C{i} {style}")

    lines.append("```")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# DAG Rendering (multi-path attack graphs)
# ---------------------------------------------------------------------------


def _render_mermaid_dag(
    dag: AttackDAG, attack_type: str
) -> tuple[str, str]:
    """Render a multi-path attack graph as Mermaid flowchart.

    Returns ``(raw_mermaid, markdown)``:

    * **raw_mermaid** — pure Mermaid code (no fences) with path
      descriptions embedded as ``%%`` comments.  Suitable for ``.mmd``
      files consumed directly by Mermaid CLI, VS Code Mermaid Preview,
      or `mermaid.live <https://mermaid.live>`_.
    * **markdown** — fenced ``\u0060\u0060\u0060mermaid`` block followed by a
      human-readable path legend.  Suitable for GitHub / VS Code
      markdown rendering.
    """
    # --- Path metadata used in both forms ---
    path_meta: list[tuple[str, str]] = []
    for p in dag.paths:
        path_meta.append((p.get("path_id", "?"), p.get("description", "")))

    conv_labels: list[str] = []
    for ctid in dag.convergence_points:
        for nk, node in dag.nodes.items():
            if node.technique_id == ctid:
                conv_labels.append(f"{ctid} ({node.tactic})")
                break

    # --- Build raw Mermaid lines (no fences) ---
    mmd: list[str] = []

    # Embed path descriptions as Mermaid comments at the top
    for pid, desc in path_meta:
        mmd.append(f"%% Path: {pid} - {desc}")
    if conv_labels:
        mmd.append(f"%% Convergence: {', '.join(conv_labels)}")
    mmd.append("")

    mmd.append("flowchart TB")
    mmd.append(f'    subgraph attack["{attack_type.upper()} Attack Graph"]')
    mmd.append("    direction TB")

    entry_set = set(dag.entry_points)

    # Assign short node IDs and render node labels
    id_map: dict[str, str] = {}
    for i, (nk, node) in enumerate(dag.nodes.items()):
        nid = f"N{i}"
        id_map[nk] = nid
        name = node.tactic or node.technique_id
        label = f"{name}<br/><small>{node.technique_id}"
        if node.technique_name:
            label += f" - {node.technique_name[:30]}"
        label += "</small>"
        # Annotate entry-point nodes with their path name(s)
        if nk in entry_set and node.path_ids:
            path_tag = " | ".join(node.path_ids)
            label = f"<b>{path_tag}</b><br/>" + label
        mmd.append(f'    {nid}(["{label}"])')

    # Render edges
    for nk, node in dag.nodes.items():
        src = id_map[nk]
        for target_nk in node.leads_to:
            if target_nk in id_map:
                dst = id_map[target_nk]
                mmd.append(f"    {src} --> {dst}")

    mmd.append("    end")
    mmd.append("")

    # Color legend subgraph (rendered outside the attack subgraph)
    mmd.append('    subgraph legend[" "]')
    mmd.append("    direction LR")
    mmd.append('    LE["Entry Point"]')
    mmd.append('    LM["Mid-chain"]')
    mmd.append('    LX["Exit / Terminal"]')
    mmd.append('    LC["Convergence"]')
    mmd.append('    LG["Has Controls"]')
    mmd.append("    end")
    mmd.append("")

    # Style nodes by role
    convergence_set = set(dag.convergence_points)
    branch_set = set(dag.branch_points)
    exit_set = set(dag.exit_points)

    for nk, node in dag.nodes.items():
        nid = id_map[nk]
        if node.technique_id in convergence_set:
            mmd.append(f"    style {nid} fill:#ffe0b2,stroke:#e65100")
        elif nk in entry_set:
            mmd.append(f"    style {nid} fill:#bbdefb,stroke:#1565c0")
        elif nk in exit_set:
            mmd.append(f"    style {nid} fill:#ffcdd2,stroke:#b71c1c")
        elif node.controls:
            mmd.append(f"    style {nid} fill:#ccffcc,stroke:#00cc00")
        else:
            mmd.append(f"    style {nid} fill:#ffffcc,stroke:#cccc00")

    # Style legend nodes to match the role colors
    mmd.append("    style LE fill:#bbdefb,stroke:#1565c0")
    mmd.append("    style LM fill:#ffffcc,stroke:#cccc00")
    mmd.append("    style LX fill:#ffcdd2,stroke:#b71c1c")
    mmd.append("    style LC fill:#ffe0b2,stroke:#e65100")
    mmd.append("    style LG fill:#ccffcc,stroke:#00cc00")
    mmd.append("    style legend fill:#f5f5f5,stroke:#999")

    raw_mermaid = "\n".join(mmd)

    # --- Build markdown form (fenced + path legend) ---
    md_lines = [f"```mermaid", raw_mermaid, "```"]
    md_lines.append("")
    md_lines.append("**Paths:**")
    for pid, desc in path_meta:
        md_lines.append(f"- **{pid}**: {desc}")
    if conv_labels:
        md_lines.append("")
        md_lines.append(f"**Convergence:** {', '.join(conv_labels)}")

    markdown = "\n".join(md_lines)

    return raw_mermaid, markdown


def _toposort_layers(dag: AttackDAG) -> list[list[str]]:
    """Topological sort of DAG nodes into layers (Kahn's algorithm).

    Each layer contains nodes whose predecessors are all in earlier layers.
    Nodes in the same layer can be rendered side-by-side.
    """
    # Build in-degree map
    in_degree: dict[str, int] = {tid: 0 for tid in dag.nodes}
    for node in dag.nodes.values():
        for target in node.leads_to:
            if target in in_degree:
                in_degree[target] += 1

    # Seed with entry points (in-degree 0)
    queue = [tid for tid, d in in_degree.items() if d == 0]
    layers: list[list[str]] = []

    while queue:
        layers.append(sorted(queue))
        next_queue: list[str] = []
        for tid in queue:
            for target in dag.nodes[tid].leads_to:
                if target in in_degree:
                    in_degree[target] -= 1
                    if in_degree[target] == 0:
                        next_queue.append(target)
        queue = next_queue

    # Append any remaining nodes (cycles or disconnected)
    placed = {tid for layer in layers for tid in layer}
    remaining = [tid for tid in dag.nodes if tid not in placed]
    if remaining:
        layers.append(remaining)

    return layers


def _render_ascii_dag(dag: AttackDAG, attack_type: str) -> str:
    """Render a multi-path attack graph as per-path ASCII chains.

    Each path is rendered as its own vertical chain, matching the visual
    flow of the Mermaid output.  Shared nodes (convergence points) are
    annotated with cross-references to the other paths that share them.
    """
    box_width = 64
    lines: list[str] = []
    convergence_set = set(dag.convergence_points)
    entry_set = set(dag.entry_points)
    exit_set = set(dag.exit_points)

    # --- Header ---
    header_w = box_width + 4
    lines.append("")
    lines.append("+" + "=" * header_w + "+")
    lines.append("|" + f" ATTACK GRAPH - {attack_type.upper()} ".center(header_w) + "|")
    lines.append("|" + f" {len(dag.paths)} path(s), {len(dag.nodes)} techniques ".center(header_w) + "|")
    lines.append("+" + "=" * header_w + "+")

    # --- Render each path as a separate vertical chain ---
    for path_dict in dag.paths:
        pid = path_dict.get("path_id", "?")
        desc = path_dict.get("description", "")

        lines.append("")
        lines.append("  " + "\u2550" * box_width)
        lines.append(f"  PATH: {pid}")
        if desc:
            # Wrap long descriptions
            while desc:
                lines.append(f"  {desc[:box_width]}")
                desc = desc[box_width:]
        lines.append("  " + "\u2550" * box_width)

        # Collect node keys belonging to this path
        path_node_set = {nk for nk, n in dag.nodes.items() if pid in n.path_ids}

        # Find this path's entry node(s)
        path_entries = [nk for nk in path_node_set if nk in entry_set]
        if not path_entries:
            # Fallback: nodes with no in-path predecessors
            targeted = set()
            for nk in path_node_set:
                for t in dag.nodes[nk].leads_to:
                    if t in path_node_set:
                        targeted.add(t)
            path_entries = [nk for nk in path_node_set if nk not in targeted]

        # BFS walk from entries following leads_to within path nodes
        ordered: list[str] = []
        visited: set[str] = set()
        queue = list(path_entries)
        while queue:
            nk = queue.pop(0)
            if nk in visited:
                continue
            visited.add(nk)
            ordered.append(nk)
            for target in dag.nodes[nk].leads_to:
                if target in path_node_set and target not in visited:
                    queue.append(target)

        # Append any remaining unvisited path nodes
        for nk in path_node_set:
            if nk not in visited:
                ordered.append(nk)

        for idx, nk in enumerate(ordered):
            node = dag.nodes[nk]

            # Connector between nodes
            if idx > 0:
                lines.append(f"  {'':6s}\u2502")
                lines.append(f"  {'':6s}\u25bc")

            # Annotation tags
            tags: list[str] = []
            if nk in entry_set:
                tags.append("\u25b7 ENTRY")
            if nk in exit_set:
                tags.append("\u25a0 EXIT")
            if node.technique_id in convergence_set:
                tags.append("\u25c6 CONVERGE")
            tag_str = " ".join(tags)

            # Box
            lines.append("  +" + "-" * box_width + "+")
            header = f" [{node.technique_id}] {node.tactic or '?'}"
            if tag_str:
                header += f"  {tag_str}"
            lines.append("  |" + header.ljust(box_width) + "|")
            if node.technique_name:
                lines.append("  |" + f"   {node.technique_name[:box_width - 4]}".ljust(box_width) + "|")
            # Cross-reference for shared nodes
            other_paths = [p for p in node.path_ids if p != pid]
            if other_paths:
                xref = ", ".join(other_paths)[:box_width - 16]
                lines.append("  |" + f"   also in: {xref}".ljust(box_width) + "|")
            # Controls
            for ctrl in node.controls[:3]:
                cn = ctrl.get("control_name", "?")
                eff = ctrl.get("effectiveness_rating", "?")
                lines.append("  |" + f"   \u2713 {cn} ({eff})"[:box_width].ljust(box_width) + "|")
            for gap in node.gaps_detected[:2]:
                lines.append("  |" + f"   \u2717 GAP: {gap}"[:box_width].ljust(box_width) + "|")
            lines.append("  +" + "-" * box_width + "+")

    # --- Unprotected stages warning ---
    lines.append("")
    unprotected = [
        n.technique_id for nk, n in dag.nodes.items()
        if not n.controls and nk not in exit_set
    ]
    if unprotected:
        lines.append(f"  \u26a0 Unprotected stages: {', '.join(unprotected)}")

    # --- Legend ---
    lines.append("")
    lines.append("  " + "-" * (box_width + 2))
    lines.append("  Legend: \u25b7 Entry | \u25a0 Exit | \u25c6 Converge | \u25c7 Branch")
    lines.append("          \u2713 control | \u2717 gap")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Plugin Implementation
# ---------------------------------------------------------------------------

class AttackPathVisualizer:
    """Generate visual representations of attack paths."""

    def metadata(self) -> dict[str, Any]:
        return {
            "tool_name": "attack_path_visualizer",
            "version": "1.0.0",
            "pillar": "threat_modeling",
        }

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        errors: list[str] = []

        has_artifact = "artifact_id" in payload
        has_stages = "stages" in payload

        if not has_artifact and not has_stages:
            errors.append(
                "Either 'artifact_id' (json_events from threat_intel_ingester) "
                "or 'stages' list is required"
            )
        elif has_stages and not isinstance(payload["stages"], list):
            errors.append("'stages' must be a list")

        fmt = payload.get("format", "ascii")
        if fmt not in ("ascii", "mermaid", "compact", "both"):
            errors.append(f"Invalid format '{fmt}'. Must be ascii, mermaid, compact, or both.")

        if errors:
            return ValidationResult(ok=False, errors=errors)
        return ValidationResult(ok=True)

    def _load_stages_from_artifact(
        self, artifact_id: str, context: Any
    ) -> "AttackDAG | list[dict] | ToolResult":
        """Resolve a json_events artifact and extract attack stages from it."""
        artifact = next(
            (a for a in context.artifacts if a.artifact_id == artifact_id), None
        )
        if artifact is None:
            return ToolResult(
                ok=False,
                error_code="ARTIFACT_NOT_FOUND",
                message=(
                    f"Artifact '{artifact_id}' not found in session. "
                    "Use 'artifacts' to list loaded artifacts."
                ),
            )
        if artifact.artifact_type != "json_events":
            return ToolResult(
                ok=False,
                error_code="INPUT_VALIDATION_FAILED",
                message=(
                    f"Expected a json_events artifact (from threat_intel_ingester), "
                    f"got '{artifact.artifact_type}'."
                ),
            )
        try:
            with open(artifact.file_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as exc:
            return ToolResult(
                ok=False,
                error_code="ARTIFACT_UNREADABLE",
                message=f"Failed to read artifact: {exc}",
            )
        # Try multi-path DAG first (new attack_graph field)
        attack_graph = data.get("attack_graph", {})
        mitre_mappings = data.get("mitre_mappings", [])

        if attack_graph.get("paths"):
            dag = _build_dag_from_attack_graph(attack_graph, mitre_mappings)
            if dag and dag.nodes:
                return dag

        # Fall back to legacy linear builder
        stages = _build_stages_from_threat_intel(data)
        if not stages:
            return ToolResult(
                ok=False,
                error_code="NO_MITRE_MAPPINGS",
                message=(
                    "No MITRE technique mappings found in the json_events artifact. "
                    "Re-run threat_intel_ingester with an LLM connected to populate "
                    "technique mappings, or supply 'stages' manually."
                ),
            )
        return stages

    def execute(
        self,
        payload: dict[str, Any],
        context: Any,
    ) -> ToolResult:
        """Render attack path visualization."""
        fmt = payload.get("format", "ascii")
        artifact_id: str | None = payload.get("artifact_id")
        attack_type = payload.get("attack_type", "unknown")

        # Resolve source — artifact (DAG or stages) or inline stages payload
        dag: AttackDAG | None = None
        stages: list[dict] | None = None

        if artifact_id and "stages" not in payload:
            result_or_data = self._load_stages_from_artifact(artifact_id, context)
            if isinstance(result_or_data, ToolResult):
                return result_or_data
            elif isinstance(result_or_data, AttackDAG):
                dag = result_or_data
            else:
                stages = result_or_data
            if attack_type == "unknown":
                attack_type = "threat-intel"
        else:
            stages = payload["stages"]

        narrative = payload.get("attack_narrative", "")
        include_controls = payload.get("include_controls", True)

        try:
            parts: list[str] = []
            output_artifacts: list[dict[str, Any]] = []

            if dag:
                # Multi-path DAG rendering
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                art_dir = Path("workspace") / "artifacts"
                art_dir.mkdir(parents=True, exist_ok=True)

                if fmt in ("ascii", "both"):
                    ascii_text = _render_ascii_dag(dag, attack_type)
                    parts.append(ascii_text)
                    ascii_path = art_dir / f"attack_path_ascii_{ts}.txt"
                    ascii_path.write_text(ascii_text, encoding="utf-8")
                    output_artifacts.append({
                        "artifact_id": f"art_ascii_{ts}",
                        "artifact_type": "text",
                        "file_path": str(ascii_path),
                    })

                if fmt == "compact":
                    path_count = len(dag.paths)
                    node_count = len(dag.nodes)
                    conv = len(dag.convergence_points)
                    compact_text = (
                        f"[{attack_type.upper()}] "
                        f"{path_count} path(s), {node_count} techniques, "
                        f"{conv} convergence point(s): "
                        + " \u2192 ".join(
                            f"{n.tactic}({n.technique_id})"
                            for n in dag.nodes.values()
                        )
                    )
                    parts.append(compact_text)
                    compact_path = art_dir / f"attack_path_compact_{ts}.txt"
                    compact_path.write_text(compact_text, encoding="utf-8")
                    output_artifacts.append({
                        "artifact_id": f"art_compact_{ts}",
                        "artifact_type": "text",
                        "file_path": str(compact_path),
                    })

                if fmt in ("mermaid", "both"):
                    raw_mermaid, markdown = _render_mermaid_dag(
                        dag, attack_type
                    )
                    parts.append(markdown)

                    # .mmd — raw Mermaid code, directly usable in
                    # Mermaid CLI, VS Code preview, or mermaid.live
                    mmd_path = art_dir / f"attack_path_mermaid_{ts}.mmd"
                    mmd_path.write_text(raw_mermaid, encoding="utf-8")
                    output_artifacts.append({
                        "artifact_id": f"art_mermaid_{ts}",
                        "artifact_type": "text",
                        "file_path": str(mmd_path),
                    })

                    # .md — fenced Mermaid + path legend, renders in
                    # GitHub / VS Code markdown preview
                    md_path = art_dir / f"attack_path_mermaid_{ts}.md"
                    md_path.write_text(markdown, encoding="utf-8")
                    output_artifacts.append({
                        "artifact_id": f"art_mermaid_md_{ts}",
                        "artifact_type": "text",
                        "file_path": str(md_path),
                    })

                visualization = "\n".join(parts)
                return ToolResult(
                    ok=True,
                    result={
                        "format": fmt,
                        "visualization": visualization,
                        "stages_rendered": len(dag.nodes),
                        "missing_required": 0,
                        "path_count": len(dag.paths),
                        "convergence_points": dag.convergence_points,
                        "branch_points": dag.branch_points,
                        "source": f"artifact:{artifact_id}",
                    },
                    output_artifacts=output_artifacts or None,
                )

            else:
                # Legacy linear rendering (existing code, unchanged)
                present = [s for s in stages if s.get("stage_present", True)]
                missing_req = [
                    s for s in stages
                    if not s.get("stage_present", True)
                    and s.get("relevance") == "required"
                ]

                if fmt in ("ascii", "both"):
                    parts.append(_render_ascii(stages, attack_type, narrative))
                if fmt == "compact":
                    parts.append(_render_compact(stages, attack_type))
                if fmt in ("mermaid", "both"):
                    parts.append(_render_mermaid(stages, attack_type, include_controls))

                visualization = "\n".join(parts)
                return ToolResult(
                    ok=True,
                    result={
                        "format": fmt,
                        "visualization": visualization,
                        "stages_rendered": len(present),
                        "missing_required": len(missing_req),
                        "source": f"artifact:{artifact_id}" if artifact_id else "payload",
                    },
                )

        except Exception as e:
            return ToolResult(
                ok=False,
                error_code="INTERNAL_ERROR",
                message=str(e),
            )

    def summarize_for_llm(self, result: ToolResult) -> str:
        """Compress output for LLM context."""
        if not result.ok:
            return f"attack_path_visualizer failed: {result.message}"

        data = result.result or {}
        rendered = data.get("stages_rendered", 0)
        missing = data.get("missing_required", 0)
        fmt = data.get("format", "?")
        path_count = data.get("path_count")
        convergence = data.get("convergence_points", [])

        if path_count:
            summary = (
                f"Rendered {rendered} techniques across {path_count} attack path(s) "
                f"({fmt} format)."
            )
            if convergence:
                summary += f" Convergence at: {', '.join(convergence)}."
        else:
            summary = f"Rendered {rendered} attack stages ({fmt} format)."

        if missing:
            summary += f" {missing} required stage(s) missing."

        # List output files
        artifacts = result.output_artifacts or []
        if artifacts:
            file_list = ", ".join(
                a.get("file_path", a.get("artifact_id", "?"))
                for a in artifacts
            )
            summary += f" Output files: {file_list}."

        # Include compact flow if available, truncate if too long
        viz = data.get("visualization", "")
        if len(viz) > 1500:
            lines = viz.split("\n")
            preview = "\n".join(lines[:20])
            summary += f"\n{preview}\n... (truncated)"
        elif viz:
            summary += f"\n{viz}"

        return summary[:2000]
