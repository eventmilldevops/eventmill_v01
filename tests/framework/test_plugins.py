"""
Tests for plugin loading and management.
"""

import pytest
from pathlib import Path

from framework.plugins import (
    PluginLoader,
    PluginManifest,
    LoadedPlugin,
    ToolResult,
    ValidationResult,
)


class TestPluginLoader:
    """Tests for PluginLoader."""
    
    def test_discover_plugins(self, temp_plugins_dir: Path):
        """Test discovering plugins from directory."""
        loader = PluginLoader(temp_plugins_dir)
        discovered = loader.discover_all()
        
        assert "test_plugin" in discovered
    
    def test_get_plugin(self, temp_plugins_dir: Path):
        """Test getting a loaded plugin by name."""
        loader = PluginLoader(temp_plugins_dir)
        loader.discover_all()
        
        plugin = loader.get("test_plugin")
        assert plugin is not None
        assert plugin.tool_name == "test_plugin"
    
    def test_get_by_pillar(self, temp_plugins_dir: Path):
        """Test getting plugins by pillar."""
        loader = PluginLoader(temp_plugins_dir)
        loader.discover_all()
        
        plugins = loader.get_by_pillar("log_analysis")
        assert len(plugins) == 1
        assert plugins[0].tool_name == "test_plugin"
    
    def test_get_manifest(self, temp_plugins_dir: Path):
        """Test getting plugin manifest."""
        loader = PluginLoader(temp_plugins_dir)
        loader.discover_all()
        
        manifest = loader.get_manifest("test_plugin")
        assert manifest is not None
        assert manifest.tool_name == "test_plugin"
        assert manifest.pillar == "log_analysis"
        assert manifest.version == "1.0.0"
    
    def test_get_capabilities(self, temp_plugins_dir: Path):
        """Test getting plugin capabilities."""
        loader = PluginLoader(temp_plugins_dir)
        loader.discover_all()
        
        caps = loader.get_capabilities("test_plugin")
        assert "test:basic" in caps
    
    def test_find_by_capability(self, temp_plugins_dir: Path):
        """Test finding plugins by capability."""
        loader = PluginLoader(temp_plugins_dir)
        loader.discover_all()
        
        plugins = loader.find_by_capability("test:basic")
        assert len(plugins) == 1
        assert plugins[0].tool_name == "test_plugin"
    
    def test_find_by_artifact_consumed(self, temp_plugins_dir: Path):
        """Test finding plugins by consumed artifact type."""
        loader = PluginLoader(temp_plugins_dir)
        loader.discover_all()
        
        plugins = loader.find_by_artifact_consumed("text")
        assert len(plugins) == 1
        assert plugins[0].tool_name == "test_plugin"
    
    def test_find_by_artifact_produced(self, temp_plugins_dir: Path):
        """Test finding plugins by produced artifact type."""
        loader = PluginLoader(temp_plugins_dir)
        loader.discover_all()
        
        plugins = loader.find_by_artifact_produced("json_events")
        assert len(plugins) == 1
    
    def test_plugin_instance(self, temp_plugins_dir: Path):
        """Test getting plugin instance."""
        loader = PluginLoader(temp_plugins_dir)
        loader.discover_all()
        
        plugin = loader.get("test_plugin")
        instance = plugin.get_instance()
        
        # Test metadata
        metadata = instance.metadata()
        assert metadata["tool_name"] == "test_plugin"
        
        # Test validation
        valid_result = instance.validate_inputs({"test_input": "hello"})
        assert valid_result.ok
        
        invalid_result = instance.validate_inputs({})
        assert not invalid_result.ok
        
        # Test execution
        result = instance.execute({"test_input": "hello"}, None)
        assert result.ok
        assert result.result["processed"] == "hello"
        
        # Test summarize
        summary = instance.summarize_for_llm(result)
        assert "successfully" in summary


class TestPluginManifest:
    """Tests for PluginManifest."""
    
    def test_manifest_required_fields(self, temp_plugins_dir: Path):
        """Test that manifest has all required fields."""
        loader = PluginLoader(temp_plugins_dir)
        loader.discover_all()
        
        manifest = loader.get_manifest("test_plugin")
        
        # Required fields
        assert manifest.tool_name == "test_plugin"
        assert manifest.version == "1.0.0"
        assert manifest.pillar == "log_analysis"
        assert manifest.display_name == "Test Plugin"
        assert manifest.description_short
        assert manifest.entry_point == "tool.py"
        assert manifest.class_name == "TestPlugin"
    
    def test_manifest_optional_fields(self, temp_plugins_dir: Path):
        """Test manifest optional fields with defaults."""
        loader = PluginLoader(temp_plugins_dir)
        loader.discover_all()
        
        manifest = loader.get_manifest("test_plugin")
        
        # Optional fields should have values or defaults
        assert isinstance(manifest.artifacts_consumed, list)
        assert isinstance(manifest.artifacts_produced, list)
        assert isinstance(manifest.capabilities, list)
        assert manifest.timeout_class in ["fast", "medium", "slow"]
        assert isinstance(manifest.safe_for_auto_invoke, bool)
        assert isinstance(manifest.requires_llm, bool)
        assert manifest.model_tier in ["light", "heavy", "none"]

    def test_manifest_model_tier_defaults_to_light(self, temp_plugins_dir: Path):
        """A manifest omitting model_tier gets the cheap tier, not the costly one."""
        loader = PluginLoader(temp_plugins_dir)
        loader.discover_all()

        manifest = loader.get_manifest("test_plugin")
        assert "model_tier" not in manifest.data
        assert manifest.model_tier == "light"

    def test_shipped_manifests_declare_a_valid_model_tier(self):
        """Every real plugin's declared tier must be one the framework understands."""
        loader = PluginLoader(Path(__file__).parents[2] / "plugins")
        loader.discover_all()

        plugins = loader.list_all()
        assert plugins, "no plugins discovered"
        for plugin in plugins:
            assert plugin.manifest.model_tier in ("light", "heavy", "none"), (
                f"{plugin.tool_name} declares model_tier="
                f"{plugin.manifest.model_tier!r}"
            )

    def test_manifest_to_dict(self, temp_plugins_dir: Path):
        """Test converting manifest to dictionary."""
        loader = PluginLoader(temp_plugins_dir)
        loader.discover_all()
        
        manifest = loader.get_manifest("test_plugin")
        data = manifest.to_dict()
        
        assert isinstance(data, dict)
        assert data["tool_name"] == "test_plugin"
