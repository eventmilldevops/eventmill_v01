"""
Tests for routing engine.
"""

import json

import pytest
from pathlib import Path

from framework.routing import Router, RouterConfig, RoutingResult
from framework.plugins import PluginLoader


class TestRouterConfig:
    """Tests for RouterConfig."""
    
    def test_load_from_directory(self, routing_config_dir: Path):
        """Test loading config from directory."""
        config = RouterConfig.load_from_directory(routing_config_dir)
        
        assert "log_analysis" in config.pillars
        assert "log_analysis" in config.adjacency_map
        assert "log_analysis" in config.keyword_rules


class TestExpansionMode:
    """expansion_mode comes from adjacency.json, not only from the default."""

    def _config_dir(self, tmp_path: Path, routing_config_dir: Path, mode) -> Path:
        """Copy the fixture config, rewriting adjacency.json's expansion_mode."""
        target = tmp_path / "config"
        target.mkdir()
        for src in routing_config_dir.iterdir():
            data = json.loads(src.read_text())
            if src.name == "adjacency.json" and mode is not None:
                data["expansion_mode"] = mode
            (target / src.name).write_text(json.dumps(data))
        return target

    def test_reads_mode_from_config(self, tmp_path: Path, routing_config_dir: Path):
        config = RouterConfig.load_from_directory(
            self._config_dir(tmp_path, routing_config_dir, "adjacent")
        )
        assert config.expansion_mode == "adjacent"

    def test_defaults_to_strict_when_absent(self, routing_config_dir: Path):
        config = RouterConfig.load_from_directory(routing_config_dir)
        assert config.expansion_mode == "strict"

    def test_unknown_mode_falls_back_to_strict(
        self, tmp_path: Path, routing_config_dir: Path
    ):
        config = RouterConfig.load_from_directory(
            self._config_dir(tmp_path, routing_config_dir, "broad")
        )
        assert config.expansion_mode == "strict"

    def test_shipped_config_declares_a_valid_mode(self):
        config = RouterConfig.load_from_directory(
            Path(__file__).parents[2] / "framework" / "routing" / "config"
        )
        assert config.expansion_mode in ("strict", "adjacent")

    def test_adjacent_mode_reaches_adjacent_pillars(self, tmp_path: Path):
        """The adjacency map only has an effect once the mode selects it."""
        repo = Path(__file__).parents[2]
        loader = PluginLoader(repo / "plugins")
        loader.discover_all()

        shipped = repo / "framework" / "routing" / "config"
        target = tmp_path / "config"
        target.mkdir()
        for src in shipped.iterdir():
            data = json.loads(src.read_text())
            if src.name == "adjacency.json":
                data["expansion_mode"] = "adjacent"
            (target / src.name).write_text(json.dumps(data))

        strict = Router(loader, RouterConfig.load_from_directory(shipped))
        adjacent = Router(loader, RouterConfig.load_from_directory(target))
        query = dict(user_input="look at the network traffic", active_pillar="threat_modeling")

        assert not [t for t in strict.route(**query).scores if t.startswith("pcap_")]
        assert [t for t in adjacent.route(**query).scores if t.startswith("pcap_")]

    def test_declaration_outranks_adjacency_in_adjacent_mode(self, tmp_path: Path):
        """A declared tool keeps its 0.75, and is scored once, not twice."""
        repo = Path(__file__).parents[2]
        loader = PluginLoader(repo / "plugins")
        loader.discover_all()

        target = tmp_path / "config"
        target.mkdir()
        for src in (repo / "framework" / "routing" / "config").iterdir():
            data = json.loads(src.read_text())
            if src.name == "adjacency.json":
                data["expansion_mode"] = "adjacent"
            (target / src.name).write_text(json.dumps(data))

        router = Router(loader, RouterConfig.load_from_directory(target))
        result = router.route(
            user_input="ingest this threat intelligence report",
            active_pillar="threat_modeling",
        )

        assert result.scores["threat_intel_ingester"].pillar_match == 0.75
        assert result.candidate_tools.count("threat_intel_ingester") == 1


class TestAlsoUsefulIn:
    """A tool that declares another pillar is routable there."""

    @pytest.fixture
    def router(self) -> Router:
        """A router over the shipped plugins and the shipped routing config."""
        repo = Path(__file__).parents[2]
        loader = PluginLoader(repo / "plugins")
        loader.discover_all()
        config = RouterConfig.load_from_directory(repo / "framework" / "routing" / "config")
        return Router(loader, config)

    def test_declared_tool_is_a_candidate(self, router: Router):
        result = router.route(
            user_input="ingest this threat intelligence report",
            active_pillar="threat_modeling",
        )
        assert "threat_intel_ingester" in result.scores
        assert "threat_intel_ingester" in result.candidate_tools
        assert router.plugin_loader.get("threat_intel_ingester").pillar == "log_analysis"

    def test_declared_tool_scores_between_own_pillar_and_adjacent(self, router: Router):
        result = router.route(
            user_input="ingest this threat intelligence report",
            active_pillar="threat_modeling",
        )
        assert result.scores["threat_intel_ingester"].pillar_match == 0.75
        assert result.scores["threat_model_analyzer"].pillar_match == 1.0

    def test_undeclared_pillars_stay_out(self, router: Router):
        result = router.route(
            user_input="look at the network traffic",
            active_pillar="threat_modeling",
        )
        assert not [t for t in result.scores if t.startswith("pcap_")]

    def test_declaration_does_not_change_pillar_selection(self, router: Router):
        result = router.route(
            user_input="ingest this threat intelligence report",
            active_pillar="threat_modeling",
        )
        assert result.selected_pillar == "threat_modeling"

    def test_own_pillar_routing_is_unchanged(self, router: Router):
        result = router.route(
            user_input="ingest this threat intelligence report",
            active_pillar="log_analysis",
        )
        assert result.scores["threat_intel_ingester"].pillar_match == 1.0

    def test_get_tools_for_pillar_includes_declared_tools(self, router: Router):
        tools = router.get_tools_for_pillar("threat_modeling")
        assert "threat_intel_ingester" in tools
        assert "pcap_metadata_summary" not in tools


class TestRouter:
    """Tests for Router."""
    
    def test_route_with_keyword_match(
        self, temp_plugins_dir: Path, routing_config_dir: Path
    ):
        """Test routing with keyword matching."""
        loader = PluginLoader(temp_plugins_dir)
        loader.discover_all()
        
        config = RouterConfig.load_from_directory(routing_config_dir)
        router = Router(loader, config)
        
        result = router.route(
            user_input="parse this log file",
            artifact_types=[],
        )
        
        assert result.selected_pillar == "log_analysis"
        assert "test_plugin" in result.candidate_tools
    
    def test_route_with_manual_pillar(
        self, temp_plugins_dir: Path, routing_config_dir: Path
    ):
        """Test routing with manually selected pillar."""
        loader = PluginLoader(temp_plugins_dir)
        loader.discover_all()
        
        config = RouterConfig.load_from_directory(routing_config_dir)
        router = Router(loader, config)
        
        result = router.route(
            user_input="analyze something",
            active_pillar="log_analysis",
        )
        
        assert result.selected_pillar == "log_analysis"
    
    def test_route_scoring(
        self, temp_plugins_dir: Path, routing_config_dir: Path
    ):
        """Test that routing produces scores."""
        loader = PluginLoader(temp_plugins_dir)
        loader.discover_all()
        
        config = RouterConfig.load_from_directory(routing_config_dir)
        router = Router(loader, config)
        
        result = router.route(
            user_input="parse log events",
            artifact_types=["text"],
        )
        
        assert "test_plugin" in result.scores
        score = result.scores["test_plugin"]
        assert score.total > 0
    
    def test_route_explanation(
        self, temp_plugins_dir: Path, routing_config_dir: Path
    ):
        """Test that routing produces explanation."""
        loader = PluginLoader(temp_plugins_dir)
        loader.discover_all()
        
        config = RouterConfig.load_from_directory(routing_config_dir)
        router = Router(loader, config)
        
        result = router.route(user_input="test")
        
        assert result.explanation
        assert "Selected pillar" in result.explanation
    
    def test_list_pillars(
        self, temp_plugins_dir: Path, routing_config_dir: Path
    ):
        """Test listing available pillars."""
        loader = PluginLoader(temp_plugins_dir)
        loader.discover_all()
        
        config = RouterConfig.load_from_directory(routing_config_dir)
        router = Router(loader, config)
        
        pillars = router.list_pillars()
        
        assert len(pillars) >= 1
        assert any(p["name"] == "log_analysis" for p in pillars)
    
    def test_get_tools_for_pillar(
        self, temp_plugins_dir: Path, routing_config_dir: Path
    ):
        """Test getting tools for a pillar."""
        loader = PluginLoader(temp_plugins_dir)
        loader.discover_all()
        
        config = RouterConfig.load_from_directory(routing_config_dir)
        router = Router(loader, config)
        
        tools = router.get_tools_for_pillar("log_analysis")
        
        assert "test_plugin" in tools
    
    def test_routing_result_to_dict(
        self, temp_plugins_dir: Path, routing_config_dir: Path
    ):
        """Test converting routing result to dictionary."""
        loader = PluginLoader(temp_plugins_dir)
        loader.discover_all()
        
        config = RouterConfig.load_from_directory(routing_config_dir)
        router = Router(loader, config)
        
        result = router.route(user_input="test")
        data = result.to_dict()
        
        assert isinstance(data, dict)
        assert "selected_pillar" in data
        assert "candidate_tools" in data
        assert "scores" in data
