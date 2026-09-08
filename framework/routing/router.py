"""
Event Mill Router

Controls which plugins are visible to the LLM at any point in the investigation.
Implements the four-phase routing model from router_design.md.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..plugins.loader import LoadedPlugin, PluginLoader

logger = logging.getLogger("eventmill.framework.routing")


# ---------------------------------------------------------------------------
# Routing Result Types
# ---------------------------------------------------------------------------


@dataclass
class RoutingScore:
    """Score breakdown for a single tool."""
    tool_name: str
    pillar_match: float = 0.0
    artifact_match: float = 0.0
    capability_match: float = 0.0
    keyword_match: float = 0.0
    session_continuity: float = 0.0
    total: float = 0.0
    
    def compute_total(self, weights: dict[str, float]) -> float:
        """Compute weighted total score."""
        self.total = (
            self.pillar_match * weights.get("pillar", 1.0) +
            self.artifact_match * weights.get("artifact", 0.8) +
            self.capability_match * weights.get("capability", 0.6) +
            self.keyword_match * weights.get("keyword", 0.4) +
            self.session_continuity * weights.get("session", 0.3)
        )
        return self.total


@dataclass
class RoutingResult:
    """Result of a routing decision."""
    
    selected_pillar: str
    candidate_tools: list[str]
    scores: dict[str, RoutingScore]
    chain_recommendations: list[str] = field(default_factory=list)
    explanation: str = ""
    mode: str = "auto"
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "selected_pillar": self.selected_pillar,
            "candidate_tools": self.candidate_tools,
            "scores": {
                name: {
                    "pillar_match": score.pillar_match,
                    "artifact_match": score.artifact_match,
                    "capability_match": score.capability_match,
                    "keyword_match": score.keyword_match,
                    "session_continuity": score.session_continuity,
                    "total": score.total,
                }
                for name, score in self.scores.items()
            },
            "chain_recommendations": self.chain_recommendations,
            "explanation": self.explanation,
            "mode": self.mode,
        }


# ---------------------------------------------------------------------------
# Router Configuration
# ---------------------------------------------------------------------------


@dataclass
class RouterConfig:
    """Router configuration loaded from config files."""
    
    pillars: dict[str, dict[str, Any]]
    adjacency_map: dict[str, list[str]]
    keyword_rules: dict[str, list[str]]
    artifact_rules: dict[str, dict[str, Any]]
    
    # Scoring weights
    weights: dict[str, float] = field(default_factory=lambda: {
        "pillar": 1.0,
        "artifact": 0.8,
        "capability": 0.6,
        "keyword": 0.4,
        "session": 0.3,
    })
    
    # Limits
    max_candidate_tools: int = 5
    expansion_mode: str = "strict"  # strict or adjacent
    
    @classmethod
    def load_from_directory(cls, config_dir: Path) -> RouterConfig:
        """Load configuration from JSON files in a directory."""
        
        # Load pillars
        pillars_path = config_dir / "pillars.json"
        with open(pillars_path) as f:
            pillars_data = json.load(f)
        
        # Load adjacency
        adjacency_path = config_dir / "adjacency.json"
        with open(adjacency_path) as f:
            adjacency_data = json.load(f)
        
        # Load keywords
        keywords_path = config_dir / "keywords.json"
        with open(keywords_path) as f:
            keywords_data = json.load(f)
        
        # Load artifact rules
        artifact_path = config_dir / "artifact_rules.json"
        with open(artifact_path) as f:
            artifact_data = json.load(f)
        
        return cls(
            pillars=pillars_data.get("pillars", {}),
            adjacency_map=adjacency_data.get("adjacency_map", {}),
            keyword_rules=keywords_data.get("keyword_rules", {}),
            artifact_rules=artifact_data.get("artifact_pillar_mapping", {}),
        )


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------


class Router:
    """Event Mill routing engine.
    
    Implements the four-phase routing model:
    1. Pillar Selection
    2. Capability Derivation
    3. Tool Filtering and Ranking
    4. Chain Recommendation
    """
    
    def __init__(
        self,
        plugin_loader: PluginLoader,
        config: RouterConfig,
    ):
        """Initialize router.
        
        Args:
            plugin_loader: The plugin loader with discovered plugins.
            config: Router configuration.
        """
        self.plugin_loader = plugin_loader
        self.config = config
        
        # Build keyword index for fast lookup
        self._keyword_index: dict[str, str] = {}
        for pillar, keywords in config.keyword_rules.items():
            for keyword in keywords:
                self._keyword_index[keyword.lower()] = pillar
    
    def route(
        self,
        user_input: str,
        artifact_types: list[str] | None = None,
        active_pillar: str | None = None,
        recent_tools: list[str] | None = None,
        mode: str = "auto",
    ) -> RoutingResult:
        """Perform routing decision.
        
        Args:
            user_input: The user's natural language input.
            artifact_types: Types of artifacts currently loaded.
            active_pillar: Currently selected pillar (if any).
            recent_tools: Recently used tools (for session continuity).
            mode: Routing mode - "auto", "manual", or "suggest".
        
        Returns:
            RoutingResult with selected tools and explanations.
        """
        artifact_types = artifact_types or []
        recent_tools = recent_tools or []
        
        # Phase 1: Pillar Selection
        selected_pillar = self._select_pillar(
            user_input=user_input,
            artifact_types=artifact_types,
            active_pillar=active_pillar,
        )
        
        # Phase 2: Get candidate tools from pillar
        pillar_tools = self.plugin_loader.get_for_pillar(selected_pillar)
        
        # Expand to adjacent pillars if configured
        if self.config.expansion_mode == "adjacent":
            adjacent_pillars = self.config.adjacency_map.get(selected_pillar, [])
            for adj_pillar in adjacent_pillars:
                pillar_tools.extend(self.plugin_loader.get_by_pillar(adj_pillar))
            seen: set[str] = set()
            deduped: list[LoadedPlugin] = []
            for tool in pillar_tools:
                if tool.tool_name not in seen:
                    seen.add(tool.tool_name)
                    deduped.append(tool)
            pillar_tools = deduped
        
        # Phase 3: Score and rank tools
        scores = self._score_tools(
            tools=pillar_tools,
            user_input=user_input,
            artifact_types=artifact_types,
            selected_pillar=selected_pillar,
            recent_tools=recent_tools,
        )
        
        # Sort by score and limit
        sorted_tools = sorted(
            scores.keys(),
            key=lambda t: scores[t].total,
            reverse=True,
        )
        candidate_tools = sorted_tools[:self.config.max_candidate_tools]
        
        # Phase 4: Chain recommendations
        chain_recommendations = self._get_chain_recommendations(candidate_tools)
        
        # Build explanation
        explanation = self._build_explanation(
            selected_pillar=selected_pillar,
            candidate_tools=candidate_tools,
            scores=scores,
        )
        
        return RoutingResult(
            selected_pillar=selected_pillar,
            candidate_tools=candidate_tools,
            scores={name: scores[name] for name in candidate_tools},
            chain_recommendations=chain_recommendations,
            explanation=explanation,
            mode=mode,
        )
    
    def _select_pillar(
        self,
        user_input: str,
        artifact_types: list[str],
        active_pillar: str | None,
    ) -> str:
        """Phase 1: Select the investigation pillar.
        
        Priority order:
        1. Manual selection (active_pillar)
        2. Strong artifact inference
        3. Keyword matching
        4. Default to log_analysis
        """
        # Manual selection takes precedence
        if active_pillar and active_pillar in self.config.pillars:
            return active_pillar
        
        # Strong artifact inference
        for artifact_type in artifact_types:
            rule = self.config.artifact_rules.get(artifact_type, {})
            if rule.get("strength") == "strong" and rule.get("pillar"):
                return rule["pillar"]
        
        # Keyword matching
        input_lower = user_input.lower()
        pillar_scores: dict[str, int] = {}
        
        for keyword, pillar in self._keyword_index.items():
            if keyword in input_lower:
                pillar_scores[pillar] = pillar_scores.get(pillar, 0) + 1
        
        if pillar_scores:
            return max(pillar_scores, key=pillar_scores.get)
        
        # Default
        return "log_analysis"
    
    def _score_tools(
        self,
        tools: list[LoadedPlugin],
        user_input: str,
        artifact_types: list[str],
        selected_pillar: str,
        recent_tools: list[str],
    ) -> dict[str, RoutingScore]:
        """Phase 3: Score and rank tools."""
        scores: dict[str, RoutingScore] = {}
        input_lower = user_input.lower()
        
        for tool in tools:
            score = RoutingScore(tool_name=tool.tool_name)
            
            # Pillar match
            if tool.pillar == selected_pillar:
                score.pillar_match = 1.0
            elif selected_pillar in tool.manifest.also_useful_in:
                score.pillar_match = 0.75
            elif tool.pillar in self.config.adjacency_map.get(selected_pillar, []):
                score.pillar_match = 0.5
            
            # Artifact match
            consumed = tool.manifest.artifacts_consumed
            if consumed:
                matches = sum(1 for a in artifact_types if a in consumed)
                score.artifact_match = min(1.0, matches / len(consumed))
            
            # Capability match (keyword in capabilities)
            for cap in tool.manifest.capabilities:
                cap_words = cap.lower().replace("_", " ").replace(":", " ").split()
                for word in cap_words:
                    if word in input_lower:
                        score.capability_match = min(1.0, score.capability_match + 0.3)
            
            # Keyword match (tool name, tags, description)
            tool_text = " ".join([
                tool.tool_name.replace("_", " "),
                tool.manifest.display_name,
                tool.manifest.description_short,
                " ".join(tool.manifest.tags),
            ]).lower()
            
            input_words = set(input_lower.split())
            tool_words = set(tool_text.split())
            overlap = len(input_words & tool_words)
            if overlap > 0:
                score.keyword_match = min(1.0, overlap * 0.2)
            
            # Session continuity
            if tool.tool_name in recent_tools:
                recency = recent_tools.index(tool.tool_name)
                score.session_continuity = max(0, 1.0 - (recency * 0.3))
            
            # Compute total
            score.compute_total(self.config.weights)
            scores[tool.tool_name] = score
        
        return scores
    
    def _get_chain_recommendations(
        self,
        candidate_tools: list[str],
    ) -> list[str]:
        """Phase 4: Get chain recommendations based on tool outputs."""
        recommendations = []
        
        for tool_name in candidate_tools:
            manifest = self.plugin_loader.get_manifest(tool_name)
            if manifest and manifest.chains_to:
                for chain_target in manifest.chains_to:
                    if chain_target not in candidate_tools and chain_target not in recommendations:
                        recommendations.append(chain_target)
        
        return recommendations[:3]  # Limit recommendations
    
    def _build_explanation(
        self,
        selected_pillar: str,
        candidate_tools: list[str],
        scores: dict[str, RoutingScore],
    ) -> str:
        """Build human-readable explanation of routing decision."""
        lines = [
            f"Selected pillar: {selected_pillar}",
            f"Candidate tools ({len(candidate_tools)}):",
        ]
        
        for tool_name in candidate_tools:
            score = scores.get(tool_name)
            if score:
                lines.append(
                    f"  - {tool_name}: {score.total:.2f} "
                    f"(pillar={score.pillar_match:.1f}, "
                    f"artifact={score.artifact_match:.1f}, "
                    f"keyword={score.keyword_match:.1f})"
                )
        
        return "\n".join(lines)
    
    def set_pillar(self, pillar: str) -> None:
        """Manually set the active pillar.
        
        Args:
            pillar: The pillar to activate.
        
        Raises:
            ValueError: If pillar is invalid.
        """
        if pillar not in self.config.pillars:
            raise ValueError(f"Invalid pillar: {pillar}")
        
        logger.info("Manually set pillar to: %s", pillar)
    
    def list_pillars(self) -> list[dict[str, Any]]:
        """List available pillars with their status."""
        return [
            {
                "name": name,
                "display_name": info.get("display_name", name),
                "description": info.get("description", ""),
                "enabled": info.get("enabled", True),
            }
            for name, info in self.config.pillars.items()
        ]
    
    def get_tools_for_pillar(self, pillar: str) -> list[str]:
        """Get all tools offered in a pillar, including those that declare it."""
        plugins = self.plugin_loader.get_for_pillar(pillar)
        return [p.tool_name for p in plugins]
