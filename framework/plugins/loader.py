"""
Event Mill Plugin Loader

Discovery, validation, and loading of plugins from the plugins directory.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
from pathlib import Path
from typing import Any, Type

from .protocol import EventMillToolProtocol

logger = logging.getLogger("eventmill.framework.plugins")


class PluginManifest:
    """Parsed plugin manifest with validation."""
    
    def __init__(self, data: dict[str, Any], manifest_path: Path):
        self.data = data
        self.manifest_path = manifest_path
        self.plugin_dir = manifest_path.parent
        
        # Required fields
        self.tool_name: str = data["tool_name"]
        self.version: str = data["version"]
        self.pillar: str = data["pillar"]
        self.display_name: str = data["display_name"]
        self.description_short: str = data["description_short"]
        self.entry_point: str = data["entry_point"]
        self.class_name: str = data["class_name"]
        
        # Optional fields with defaults
        self.description_long: str = data.get("description_long", "")
        self.author: str = data.get("author", "")
        self.artifacts_consumed: list[str] = data.get("artifacts_consumed", [])
        self.artifacts_produced: list[str] = data.get("artifacts_produced", [])
        self.capabilities: list[str] = data.get("capabilities", [])
        self.timeout_class: str = data.get("timeout_class", "medium")
        self.cost_hint: str = data.get("cost_hint", "low")
        self.safe_for_auto_invoke: bool = data.get("safe_for_auto_invoke", False)
        self.requires_llm: bool = data.get("requires_llm", False)
        self.dependencies: list[str] = data.get("dependencies", [])
        self.stability: str = data.get("stability", "experimental")
        self.tags: list[str] = data.get("tags", [])
        self.chains_to: list[str] = data.get("chains_to", [])
        self.chains_from: list[str] = data.get("chains_from", [])
    
    def get_entry_point_path(self) -> Path:
        """Get the full path to the entry point module."""
        return self.plugin_dir / self.entry_point
    
    def to_dict(self) -> dict[str, Any]:
        """Convert manifest to dictionary."""
        return self.data


class LoadedPlugin:
    """A loaded and validated plugin."""
    
    def __init__(
        self,
        manifest: PluginManifest,
        plugin_class: Type[EventMillToolProtocol],
    ):
        self.manifest = manifest
        self.plugin_class = plugin_class
        self._instance: EventMillToolProtocol | None = None
    
    @property
    def tool_name(self) -> str:
        return self.manifest.tool_name
    
    @property
    def pillar(self) -> str:
        return self.manifest.pillar
    
    def get_instance(self) -> EventMillToolProtocol:
        """Get or create the plugin instance."""
        if self._instance is None:
            self._instance = self.plugin_class()
        return self._instance


class PluginLoader:
    """Discovers and loads plugins from the plugins directory."""
    
    def __init__(self, plugins_dir: Path):
        """Initialize plugin loader.
        
        Args:
            plugins_dir: Path to the plugins directory.
        """
        self.plugins_dir = plugins_dir
        self._plugins: dict[str, LoadedPlugin] = {}
        self._by_pillar: dict[str, list[str]] = {}
    
    def discover_all(self) -> list[str]:
        """Discover all plugins in the plugins directory.
        
        Returns:
            List of discovered plugin names.
        """
        discovered = []
        
        for pillar_dir in self.plugins_dir.iterdir():
            if not pillar_dir.is_dir() or pillar_dir.name.startswith("_"):
                continue
            
            for plugin_dir in pillar_dir.iterdir():
                if not plugin_dir.is_dir() or plugin_dir.name.startswith("_"):
                    continue
                
                manifest_path = plugin_dir / "manifest.json"
                if not manifest_path.exists():
                    logger.warning(
                        "Plugin directory %s missing manifest.json",
                        plugin_dir.name,
                    )
                    continue
                
                try:
                    plugin = self._load_plugin(manifest_path)
                    self._plugins[plugin.tool_name] = plugin
                    
                    # Index by pillar
                    if plugin.pillar not in self._by_pillar:
                        self._by_pillar[plugin.pillar] = []
                    self._by_pillar[plugin.pillar].append(plugin.tool_name)
                    
                    discovered.append(plugin.tool_name)
                    logger.info(
                        "Loaded plugin: %s (pillar=%s)",
                        plugin.tool_name,
                        plugin.pillar,
                    )
                except Exception as e:
                    logger.error(
                        "Failed to load plugin %s: %s",
                        plugin_dir.name,
                        e,
                    )
        
        return discovered
    
    def _load_plugin(self, manifest_path: Path) -> LoadedPlugin:
        """Load a single plugin from its manifest.
        
        Args:
            manifest_path: Path to the manifest.json file.
        
        Returns:
            LoadedPlugin instance.
        
        Raises:
            ValueError: If manifest is invalid.
            ImportError: If plugin module cannot be loaded.
        """
        # Parse manifest
        with open(manifest_path) as f:
            manifest_data = json.load(f)
        
        manifest = PluginManifest(manifest_data, manifest_path)
        
        # Validate pillar matches directory
        pillar_dir = manifest_path.parent.parent.name
        if manifest.pillar != pillar_dir:
            raise ValueError(
                f"Manifest pillar '{manifest.pillar}' does not match "
                f"directory '{pillar_dir}'"
            )
        
        # Load the plugin module
        entry_point_path = manifest.get_entry_point_path()
        if not entry_point_path.exists():
            raise ImportError(
                f"Entry point not found: {entry_point_path}"
            )
        
        # Use a flat module name to avoid parent-package lookup failures
        # (dotted names require parent packages in sys.modules)
        module_name = f"eventmill_plugin_{manifest.pillar}_{manifest.tool_name}"
        spec = importlib.util.spec_from_file_location(
            module_name,
            entry_point_path,
        )
        if spec is None or spec.loader is None:
            raise ImportError(
                f"Cannot create module spec for {entry_point_path}"
            )
        
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        
        # Get the plugin class
        if not hasattr(module, manifest.class_name):
            raise ImportError(
                f"Class '{manifest.class_name}' not found in {entry_point_path}"
            )
        
        plugin_class = getattr(module, manifest.class_name)
        
        return LoadedPlugin(manifest, plugin_class)
    
    def get(self, tool_name: str) -> LoadedPlugin | None:
        """Get a loaded plugin by name.
        
        Args:
            tool_name: The plugin tool name.
        
        Returns:
            LoadedPlugin or None if not found.
        """
        return self._plugins.get(tool_name)
    
    def get_by_pillar(self, pillar: str) -> list[LoadedPlugin]:
        """Get all plugins for a pillar.
        
        Args:
            pillar: The pillar name.
        
        Returns:
            List of LoadedPlugin instances.
        """
        tool_names = self._by_pillar.get(pillar, [])
        return [self._plugins[name] for name in tool_names]
    
    def list_all(self) -> list[LoadedPlugin]:
        """List all loaded plugins."""
        return list(self._plugins.values())
    
    def list_pillars(self) -> list[str]:
        """List all pillars with loaded plugins."""
        return list(self._by_pillar.keys())
    
    def get_manifest(self, tool_name: str) -> PluginManifest | None:
        """Get the manifest for a plugin.
        
        Args:
            tool_name: The plugin tool name.
        
        Returns:
            PluginManifest or None if not found.
        """
        plugin = self._plugins.get(tool_name)
        if plugin:
            return plugin.manifest
        return None
    
    def get_capabilities(self, tool_name: str) -> list[str]:
        """Get the capabilities for a plugin.
        
        Args:
            tool_name: The plugin tool name.
        
        Returns:
            List of capability strings.
        """
        manifest = self.get_manifest(tool_name)
        if manifest:
            return manifest.capabilities
        return []
    
    def find_by_capability(self, capability: str) -> list[LoadedPlugin]:
        """Find plugins with a specific capability.
        
        Args:
            capability: The capability to search for.
        
        Returns:
            List of matching LoadedPlugin instances.
        """
        return [
            plugin
            for plugin in self._plugins.values()
            if capability in plugin.manifest.capabilities
        ]
    
    def find_by_artifact_consumed(self, artifact_type: str) -> list[LoadedPlugin]:
        """Find plugins that consume a specific artifact type.
        
        Args:
            artifact_type: The artifact type to search for.
        
        Returns:
            List of matching LoadedPlugin instances.
        """
        return [
            plugin
            for plugin in self._plugins.values()
            if artifact_type in plugin.manifest.artifacts_consumed
        ]
    
    def find_by_artifact_produced(self, artifact_type: str) -> list[LoadedPlugin]:
        """Find plugins that produce a specific artifact type.
        
        Args:
            artifact_type: The artifact type to search for.
        
        Returns:
            List of matching LoadedPlugin instances.
        """
        return [
            plugin
            for plugin in self._plugins.values()
            if artifact_type in plugin.manifest.artifacts_produced
        ]
