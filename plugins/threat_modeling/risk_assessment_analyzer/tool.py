"""
Risk Assessment Analyzer — Validate attack paths against MITRE ATT&CK stages with control scoring.

Ported from Event Mill v1.0 risk_assessment.py with improvements:
- Conforms to EventMillToolProtocol
- Self-contained attack type/stage mappings (no external context files required)
- Structured JSON output with confidence scoring
- Deterministic stage validation (no LLM needed for validate_stages)
- LLM integration via ExecutionContext.llm_query for document analysis
- summarize_for_llm() for context-optimized output
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any


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
# MITRE ATT&CK Attack Stages
# ---------------------------------------------------------------------------

class AttackStage(Enum):
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    STEALTH = "Stealth"
    DEFENSE_IMPAIRMENT = "Defense Impairment"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact/Action on Objective"


# Stage names retired by a later ATT&CK release, mapped to the stage whose
# relevance they inherit.  ATT&CK v19 split "Defense Evasion" into Stealth
# and Defense Impairment; older documents and payloads still use the old name.
_LEGACY_STAGE_NAMES: dict[str, AttackStage] = {
    "Defense Evasion": AttackStage.STEALTH,
}


ATTACK_TYPE_STAGES: dict[str, dict[str, list[AttackStage]]] = {
    "ddos": {
        "required": [AttackStage.INITIAL_ACCESS, AttackStage.IMPACT],
        "optional": [AttackStage.COMMAND_AND_CONTROL],
        "not_applicable": [
            AttackStage.PERSISTENCE, AttackStage.PRIVILEGE_ESCALATION,
            AttackStage.CREDENTIAL_ACCESS, AttackStage.LATERAL_MOVEMENT,
            AttackStage.COLLECTION, AttackStage.EXFILTRATION,
        ],
    },
    "ransomware": {
        "required": [
            AttackStage.INITIAL_ACCESS, AttackStage.EXECUTION,
            AttackStage.PRIVILEGE_ESCALATION, AttackStage.IMPACT,
        ],
        "optional": [
            AttackStage.PERSISTENCE, AttackStage.STEALTH,
            AttackStage.DEFENSE_IMPAIRMENT, AttackStage.CREDENTIAL_ACCESS,
            AttackStage.DISCOVERY, AttackStage.LATERAL_MOVEMENT,
        ],
        "not_applicable": [AttackStage.EXFILTRATION],
    },
    "data_theft": {
        "required": [
            AttackStage.INITIAL_ACCESS, AttackStage.COLLECTION,
            AttackStage.EXFILTRATION,
        ],
        "optional": [
            AttackStage.EXECUTION, AttackStage.PERSISTENCE,
            AttackStage.PRIVILEGE_ESCALATION, AttackStage.STEALTH,
            AttackStage.DEFENSE_IMPAIRMENT, AttackStage.CREDENTIAL_ACCESS,
            AttackStage.DISCOVERY, AttackStage.LATERAL_MOVEMENT,
            AttackStage.COMMAND_AND_CONTROL,
        ],
        "not_applicable": [],
    },
    "apt": {
        "required": [
            AttackStage.INITIAL_ACCESS, AttackStage.EXECUTION,
            AttackStage.PERSISTENCE, AttackStage.DISCOVERY,
        ],
        "optional": [
            AttackStage.PRIVILEGE_ESCALATION, AttackStage.STEALTH,
            AttackStage.DEFENSE_IMPAIRMENT, AttackStage.CREDENTIAL_ACCESS,
            AttackStage.LATERAL_MOVEMENT, AttackStage.COLLECTION,
            AttackStage.COMMAND_AND_CONTROL, AttackStage.EXFILTRATION,
            AttackStage.IMPACT,
        ],
        "not_applicable": [],
    },
    "insider_threat": {
        "required": [AttackStage.COLLECTION, AttackStage.IMPACT],
        "optional": [AttackStage.PRIVILEGE_ESCALATION, AttackStage.EXFILTRATION],
        "not_applicable": [
            AttackStage.INITIAL_ACCESS, AttackStage.PERSISTENCE,
            AttackStage.COMMAND_AND_CONTROL,
        ],
    },
    "web_attack": {
        "required": [AttackStage.INITIAL_ACCESS, AttackStage.EXECUTION],
        "optional": [
            AttackStage.PRIVILEGE_ESCALATION, AttackStage.COLLECTION,
            AttackStage.IMPACT,
        ],
        "not_applicable": [
            AttackStage.PERSISTENCE, AttackStage.LATERAL_MOVEMENT,
            AttackStage.COMMAND_AND_CONTROL,
        ],
    },
    "generic": {
        "required": [AttackStage.INITIAL_ACCESS, AttackStage.IMPACT],
        "optional": list(AttackStage),
        "not_applicable": [],
    },
}


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class ControlAssessment:
    control_name: str
    control_type: str  # preventive | detective | responsive
    effectiveness_rating: str  # strong | moderate | weak | nominal
    evidence_basis: str  # tested | benchmark | vendor_claim | assumption
    independence_flag: bool = False
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class StageAssessment:
    name: str
    technique_claimed: str = ""
    mitre_technique_id: str = ""
    controls: list[ControlAssessment] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    gaps_detected: list[str] = field(default_factory=list)
    stage_present: bool = True
    relevance: str = "required"  # required | optional | not_applicable

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "technique_claimed": self.technique_claimed,
            "mitre_technique_id": self.mitre_technique_id,
            "controls": [c.to_dict() for c in self.controls],
            "assumptions": self.assumptions,
            "gaps_detected": self.gaps_detected,
            "stage_present": self.stage_present,
            "relevance": self.relevance,
        }


# ---------------------------------------------------------------------------
# LLM Prompt
# ---------------------------------------------------------------------------

RISK_ASSESSMENT_PROMPT = """You are a security analyst reviewing an internal risk assessment report.
Extract and validate the attack path narrative against MITRE ATT&CK stages.

CRITICAL: Only extract information explicitly stated or clearly implied. Do NOT invent stages.

ATTACK TYPE: {attack_type}
Required stages: {required_stages}
Optional stages: {optional_stages}
Not applicable stages: {not_applicable_stages}

DOCUMENT:
{document_content}

Respond with VALID JSON matching this schema:
{{
  "attack_narrative": "Brief summary",
  "stages": [
    {{
      "name": "Stage Name",
      "technique_claimed": "",
      "mitre_technique_id": "T1234",
      "controls": [
        {{
          "control_name": "",
          "control_type": "preventive|detective|responsive",
          "effectiveness_rating": "strong|moderate|weak|nominal",
          "evidence_basis": "tested|benchmark|vendor_claim|assumption",
          "independence_flag": false
        }}
      ],
      "assumptions": [],
      "gaps_detected": [],
      "stage_present": true,
      "relevance": "required|optional|not_applicable"
    }}
  ],
  "cross_stage_flags": {{
    "independence_violations": [],
    "duplicate_controls": []
  }},
  "confidence_assessment": {{
    "structural_completeness": 0.0,
    "evidence_strength": 0.0,
    "assumption_density": 0.0
  }},
  "analysis_notes": []
}}

JSON only, no markdown wrapping."""


# ---------------------------------------------------------------------------
# Plugin Implementation
# ---------------------------------------------------------------------------

class RiskAssessmentAnalyzer:
    """Validate attack paths against MITRE ATT&CK stages with control effectiveness scoring."""

    def metadata(self) -> dict[str, Any]:
        return {
            "tool_name": "risk_assessment_analyzer",
            "version": "1.0.0",
            "pillar": "threat_modeling",
        }

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        errors: list[str] = []
        action = payload.get("action")

        if not action:
            errors.append("'action' is required")
        elif action not in ("analyze", "list_attack_types", "validate_stages"):
            errors.append(f"Invalid action '{action}'.")

        if action == "analyze" and not payload.get("document_content"):
            errors.append("'document_content' is required for analyze action")

        if action == "validate_stages":
            if not payload.get("stages"):
                errors.append("'stages' list is required for validate_stages action")
            at = payload.get("attack_type", "generic")
            if at not in ATTACK_TYPE_STAGES:
                errors.append(f"Invalid attack_type '{at}'. Valid: {', '.join(ATTACK_TYPE_STAGES.keys())}")

        if action == "analyze":
            at = payload.get("attack_type", "generic")
            if at not in ATTACK_TYPE_STAGES:
                errors.append(f"Invalid attack_type '{at}'.")

        if errors:
            return ValidationResult(ok=False, errors=errors)
        return ValidationResult(ok=True)

    def execute(
        self,
        payload: dict[str, Any],
        context: Any,
    ) -> ToolResult:
        """Execute risk assessment action."""
        action = payload["action"]

        try:
            if action == "analyze":
                return self._analyze(payload, context)
            elif action == "list_attack_types":
                return self._list_attack_types()
            elif action == "validate_stages":
                return self._validate_stages(payload)
            else:
                return ToolResult(ok=False, error_code="INPUT_VALIDATION_FAILED", message=f"Unknown action: {action}")
        except Exception as e:
            return ToolResult(ok=False, error_code="INTERNAL_ERROR", message=str(e))

    def summarize_for_llm(self, result: ToolResult) -> str:
        """Compress output for LLM context."""
        if not result.ok:
            return f"risk_assessment_analyzer failed: {result.message}"

        data = result.result or {}
        action = data.get("action", "unknown")

        if action == "analyze":
            at = data.get("attack_type", "?")
            missing = data.get("missing_required_stages", [])
            conf = data.get("confidence_assessment", {})
            parts = [f"Risk assessment ({at}):"]
            if missing:
                parts.append(f"  Missing required stages: {', '.join(missing)}")
            sc = conf.get("structural_completeness", 0)
            es = conf.get("evidence_strength", 0)
            parts.append(f"  Completeness: {sc:.0%}, Evidence: {es:.0%}")
            ai = data.get("ai_analysis")
            if ai:
                parts.append(ai[:1200])
            return "\n".join(parts)

        elif action == "list_attack_types":
            types = data.get("attack_types", [])
            return f"{len(types)} attack types available: {', '.join(t['name'] for t in types)}"

        elif action == "validate_stages":
            missing = data.get("missing_required_stages", [])
            conf = data.get("confidence_assessment", {})
            total = len(data.get("stages", []))
            return (
                f"Validated {total} stages ({data.get('attack_type','?')}). "
                f"Missing: {len(missing)}. "
                f"Completeness: {conf.get('structural_completeness', 0):.0%}"
            )

        return f"risk_assessment_analyzer completed action '{action}'."

    # -------------------------------------------------------------------
    # Actions
    # -------------------------------------------------------------------

    def _analyze(self, payload: dict[str, Any], context: Any) -> ToolResult:
        """Analyze a risk assessment document with LLM."""
        content = payload["document_content"]
        attack_type = payload.get("attack_type", "generic")
        stage_config = ATTACK_TYPE_STAGES[attack_type]

        required = [s.value for s in stage_config["required"]]
        optional = [s.value for s in stage_config["optional"] if s not in stage_config["required"]]
        na = [s.value for s in stage_config["not_applicable"]]

        ai_text = None
        parsed_result = None

        if context and hasattr(context, "llm_query") and context.llm_query:
            try:
                prompt = RISK_ASSESSMENT_PROMPT.format(
                    attack_type=attack_type,
                    required_stages=", ".join(required),
                    optional_stages=", ".join(optional) or "None",
                    not_applicable_stages=", ".join(na) or "None",
                    document_content=content[:30000],
                )
                response = context.llm_query.query_text(prompt=prompt)
                if response.ok:
                    ai_text = response.text
                    # Try to parse JSON from response
                    text = ai_text.strip()
                    if text.startswith("```"):
                        lines = text.split("\n")
                        if lines[0].startswith("```"):
                            lines = lines[1:]
                        if lines and lines[-1].strip() == "```":
                            lines = lines[:-1]
                        text = "\n".join(lines)
                    try:
                        parsed_result = json.loads(text)
                    except json.JSONDecodeError:
                        pass
            except Exception:
                pass

        # Build result from parsed LLM output or empty defaults
        if parsed_result:
            stages_data = parsed_result.get("stages", [])
            missing = self._find_missing_stages(stages_data, required)
            return ToolResult(
                ok=True,
                result={
                    "action": "analyze",
                    "attack_type": attack_type,
                    "attack_narrative": parsed_result.get("attack_narrative", ""),
                    "stages": stages_data,
                    "missing_required_stages": missing,
                    "cross_stage_flags": parsed_result.get("cross_stage_flags", {}),
                    "confidence_assessment": parsed_result.get("confidence_assessment", {}),
                    "analysis_notes": parsed_result.get("analysis_notes", []),
                    "ai_analysis": ai_text,
                },
            )

        return ToolResult(
            ok=True,
            result={
                "action": "analyze",
                "attack_type": attack_type,
                "content_length": len(content),
                "required_stages": required,
                "optional_stages": optional,
                "not_applicable_stages": na,
                "stages": [],
                "missing_required_stages": required,  # All missing without LLM
                "confidence_assessment": {
                    "structural_completeness": 0.0,
                    "evidence_strength": 0.0,
                    "assumption_density": 1.0,
                },
                "ai_analysis": ai_text,
            },
        )

    def _list_attack_types(self) -> ToolResult:
        """List available attack types with stage requirements."""
        types = []
        for name, config in ATTACK_TYPE_STAGES.items():
            required = [s.value for s in config["required"]]
            optional = [s.value for s in config["optional"] if s not in config["required"]]
            na = [s.value for s in config["not_applicable"]]
            types.append({
                "name": name,
                "required_stages": required,
                "optional_stages": optional,
                "not_applicable_stages": na,
            })

        return ToolResult(
            ok=True,
            result={"action": "list_attack_types", "attack_types": types},
        )

    def _validate_stages(self, payload: dict[str, Any]) -> ToolResult:
        """Deterministic validation of stages against attack type requirements."""
        attack_type = payload.get("attack_type", "generic")
        stage_config = ATTACK_TYPE_STAGES[attack_type]
        input_stages = payload["stages"]

        required_names = {s.value for s in stage_config["required"]}

        # Build StageAssessment objects
        assessed: list[dict] = []
        present_names: set[str] = set()
        all_controls: list[str] = []
        independence_violations: list[str] = []
        duplicate_controls: list[str] = []

        for s in input_stages:
            stage = StageAssessment(
                name=s.get("name", ""),
                technique_claimed=s.get("technique_claimed", ""),
                mitre_technique_id=s.get("mitre_technique_id", ""),
                stage_present=s.get("stage_present", True),
                relevance=self._stage_relevance(s.get("name", ""), stage_config),
                assumptions=s.get("assumptions", []),
                gaps_detected=s.get("gaps_detected", []),
            )

            for c in s.get("controls", []):
                ctrl = ControlAssessment(
                    control_name=c.get("control_name", ""),
                    control_type=c.get("control_type", ""),
                    effectiveness_rating=c.get("effectiveness_rating", ""),
                    evidence_basis=c.get("evidence_basis", ""),
                    independence_flag=c.get("independence_flag", False),
                )
                stage.controls.append(ctrl)
                all_controls.append(ctrl.control_name)
                if ctrl.independence_flag:
                    independence_violations.append(
                        f"{ctrl.control_name} in stage '{stage.name}'"
                    )

            assessed.append(stage.to_dict())
            if stage.stage_present:
                present_names.add(stage.name)

        # Missing required stages
        missing = [name for name in required_names if name not in present_names]

        # Duplicate controls
        control_counts = Counter(all_controls)
        for ctrl_name, count in control_counts.items():
            if count > 1 and ctrl_name:
                duplicate_controls.append(f"{ctrl_name} appears in {count} stages")

        # Confidence metrics
        total_required = len(required_names)
        covered = total_required - len(missing) if total_required else 0
        sc = covered / total_required if total_required else 1.0

        total_controls = sum(len(s.get("controls", [])) for s in input_stages)
        tested_controls = sum(
            1 for s in input_stages
            for c in s.get("controls", [])
            if c.get("evidence_basis") in ("tested", "benchmark")
        )
        es = tested_controls / total_controls if total_controls else 0.0

        total_assumptions = sum(len(s.get("assumptions", [])) for s in input_stages)
        total_items = total_controls + total_assumptions
        ad = total_assumptions / total_items if total_items else 0.0

        return ToolResult(
            ok=True,
            result={
                "action": "validate_stages",
                "attack_type": attack_type,
                "stages": assessed,
                "missing_required_stages": missing,
                "cross_stage_flags": {
                    "independence_violations": independence_violations,
                    "duplicate_controls": duplicate_controls,
                },
                "confidence_assessment": {
                    "structural_completeness": round(sc, 2),
                    "evidence_strength": round(es, 2),
                    "assumption_density": round(ad, 2),
                },
            },
        )

    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------

    def _stage_relevance(self, stage_name: str, config: dict) -> str:
        """Determine relevance of a stage for an attack type."""
        legacy = _LEGACY_STAGE_NAMES.get(stage_name)
        if legacy is not None:
            stage_name = legacy.value
        for s in config.get("required", []):
            if s.value == stage_name:
                return "required"
        for s in config.get("not_applicable", []):
            if s.value == stage_name:
                return "not_applicable"
        return "optional"

    def _find_missing_stages(self, stages_data: list[dict], required: list[str]) -> list[str]:
        """Find required stages missing from parsed LLM output."""
        present = {s.get("name") for s in stages_data if s.get("stage_present", True)}
        return [r for r in required if r not in present]
