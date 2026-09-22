"""
Event Mill CLI Shell

Metasploit-style interactive command shell for investigations.
This is the primary user interface for Event Mill.
"""

from __future__ import annotations

import cmd
import difflib
import fnmatch
import json
import os
import random
import re
import shlex
import signal
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ..logging.structured import get_logger, setup_logging, log_user_activity, log_llm_interaction, set_user_context
from ..session.manager import SessionManager
from ..session.models import Pillar, ToolExecution, ToolExecutionStatus
from ..plugins.loader import PluginLoader, LoadedPlugin
from ..routing.router import Router, RouterConfig
from ..artifacts.registry import ArtifactRegistry, create_artifact_registration_callback
from ..llm import factory as llm_factory
from ..llm.clients.gemini import GeminiClient
from ..llm.dispatcher import (
    ContextBuilder,
    LLMDispatcher,
    TierScopedLLMClient,
)
from ..llm.model_client import LLMModelClient
from ..llm.providers import DEFAULT_PROVIDER_ID, TierSpec, load_tier_specs
from ..plugins.protocol import (
    ArtifactRef,
    ExecutionContext,
    QueryHints,
    ReferenceDataView,
    TimeoutClass,
)
from ..reference_data.mitre_attack import get_mitre_db, get_mitre_relationships
from ..cloud.resolver import (
    PILLAR_SLUGS,
    StorageResolver,
    StorageResolverConfig,
    WorkspaceFile,
    create_local_resolver,
)

logger = get_logger("cli")


# ---------------------------------------------------------------------------
# File listing support
# ---------------------------------------------------------------------------

_DURATION_RE = re.compile(r"^(\d+)\s*([smhdw])$", re.IGNORECASE)
_DURATION_UNITS = {
    "s": "seconds",
    "m": "minutes",
    "h": "hours",
    "d": "days",
    "w": "weeks",
}

_FILE_REF_RE = re.compile(r"^#(\d+)$")

FILES_DEFAULT_LIMIT = 50
FILES_SOURCES = ("pillar", "common", "all")

# Stands in for the files sitting directly at the level a folder map lists,
# so a bucket whose objects are all at one depth still maps to something.
FOLDER_LEAF = "(files here)"


def _folder_breakdown(
    files: list[WorkspaceFile],
    prefix: str = "",
) -> list[tuple[str, int, int | None]]:
    """Group *files* by the path segment one level below *prefix*.

    Returns ``(label, count, total_bytes)`` per folder, alphabetically, with
    files sitting directly at this level collected last under a marker rather
    than dropped, so a bucket whose objects are all at the root still maps to
    something.
    """
    base = prefix.rstrip("/")
    groups: dict[str, list[WorkspaceFile]] = {}
    for f in files:
        rest = f.object_path
        if base and rest.startswith(base):
            rest = rest[len(base):]
        rest = rest.lstrip("/")
        head, sep, _ = rest.partition("/")
        label = f"{head}/" if sep else FOLDER_LEAF
        groups.setdefault(label, []).append(f)

    out: list[tuple[str, int, int | None]] = []
    for label in sorted(groups, key=lambda s: (s == FOLDER_LEAF, s)):
        group = groups[label]
        sizes = [g.size_bytes for g in group if g.size_bytes is not None]
        out.append((label, len(group), sum(sizes) if sizes else None))
    return out
HISTORY_DEFAULT_LIMIT = 40


def _parse_duration(text: str) -> timedelta | None:
    """Parse a duration like ``24h`` or ``90m`` into a timedelta.

    Compound forms and calendar units are rejected rather than guessed at.
    ``m`` is minutes; there is no month unit.
    """
    match = _DURATION_RE.match(text.strip())
    if not match:
        return None
    amount, unit = match.groups()
    return timedelta(**{_DURATION_UNITS[unit.lower()]: int(amount)})


def _format_bytes(size: int | None) -> str:
    """Render a byte count in the widest unit that keeps it under 1024."""
    if size is None:
        return "-"
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            precision = 0 if unit == "B" else 1
            return f"{value:.{precision}f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def _format_age(moment: datetime | None) -> str:
    """Render a timestamp as an age relative to now."""
    if moment is None:
        return "-"
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    delta = datetime.now(timezone.utc) - moment
    seconds = int(delta.total_seconds())
    if seconds < 0:
        return "just now"
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    if seconds < 86400 * 30:
        return f"{seconds // 86400}d ago"
    return moment.strftime("%Y-%m-%d")


def _split_flags(tokens: list[str]) -> tuple[list[tuple[str, Any]], str | None]:
    """Split --key value / --key=value / --key tokens into ordered pairs.

    Returns (pairs, error). A bare flag yields True so callers can treat it
    as a boolean. The error is a printable message when parsing fails.
    """
    pairs: list[tuple[str, Any]] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if not tok.startswith("--"):
            return [], (
                f"Unexpected token {tok!r}.\n"
                "  Use --key value flags, or JSON for list/object arguments."
            )
        key, sep, inline = tok[2:].partition("=")
        if not key:
            return [], f"Invalid flag: {tok!r}. Use --key value or --key=value."
        if sep:
            pairs.append((key, inline))
            i += 1
        elif i + 1 < len(tokens) and not tokens[i + 1].startswith("--"):
            pairs.append((key, tokens[i + 1]))
            i += 2
        else:
            pairs.append((key, True))
            i += 1
    return pairs, None


@dataclass
class FilesQuery:
    """Parsed arguments for the ``files`` command."""

    prefix: str = ""
    extensions: list[str] = field(default_factory=list)
    newer_than: timedelta | None = None
    match: str = ""
    sort: str = "time"
    limit: int = FILES_DEFAULT_LIMIT
    source: str = "pillar"
    folders: bool = False


@dataclass
class FileListingEntry:
    """One numbered row of a ``files`` listing."""

    index: int
    file: WorkspaceFile
    artifact_id: str | None = None
    local_path: Path | None = None


@dataclass
class FileListing:
    """The rows a ``files`` command printed, and the context it printed them in.

    The context is what makes ``#3`` safe to reuse: a listing taken under a
    different session, pillar, or workspace folder refers to different files,
    so it is refused rather than silently resolved.
    """

    session_id: str
    pillar: str
    workspace_folder: str | None
    entries: list[FileListingEntry]


# ---------------------------------------------------------------------------
# Metasploit-style random startup banners
# ---------------------------------------------------------------------------

_BANNERS = [
    r"""
     _____ _   _ _____ _   _ _____   __  __ ___ _     _
    | ____| | | | ____| \ | |_   _| |  \/  |_ _| |   | |
    |  _| | | | |  _| |  \| | | |   | |\/| || || |   | |
    | |___| |_| | |___| |\  | | |   | |  | || || |___| |___
    |_____|\___/|_____|_| \_| |_|v0 |_|11|_|___|_____|_____|
""",
    r"""
    ╔══════════════════════════════════════════════════════╗
    ║  ███████╗██╗   ██╗███████╗███╗   ██╗████████╗       ║
    ║  ██╔════╝██║   ██║██╔════╝████╗  ██║╚══██╔══╝       ║
    ║  █████╗  ██║   ██║█████╗  ██╔██╗ ██║   ██║          ║
    ║  ██╔══╝  ╚██╗ ██╔╝██╔══╝  ██║╚██╗██║   ██║          ║
    ║  ███████╗ ╚████╔╝ ███████╗██║ ╚████║   ██║          ║
    ║  ╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝   ╚═╝          ║
    ║              M  I  L  L    v011                     ║
    ╚══════════════════════════════════════════════════════╝
""",
    r"""
               _             _
     _____   _| |_     _ __ (_) | |
    / _ \ \ / / __|   | '_ \| | | |
   |  __/\ V /| |_    | | | | | | |
    \___| \_/  \__|   |_| |_|_|_|_|
      event           mill v011
""",
    r"""
    ┌─────────────────────────────────────────┐
    │  ╺━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╸  │
    │     E V E N T   M I L L   v0.1.1       │
    │   event record analysis platform       │
    │  ╺━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╸  │
    └─────────────────────────────────────────┘
""",
    r"""
        ____                 __     __  ___ _  __  __
       / __/ _  __ ___  ___ / /_   /  |/  /(_)/ / / /
      / _/  | |/ // -_)/ _ / __/  / /|_/ // // / / /
     /___/  |___/ \__//_//_\__/v0/_/ 1/_//_//_/1/_/
""",
    r"""
      .--.      .--.      .--.      .--.
     /    \    /    \    /    \    /    \
    | EVNT |--| MILL |--| v0.1 |--| .1   |
     \    /    \    /    \    /    \    /
      `--'      `--'      `--'      `--'
      upstream of the SIEM — analysis before commitment
""",
]

# ANSI color codes — a random one is picked each launch
_COLORS = [
    "\033[1;31m",  # bold red
    "\033[1;32m",  # bold green
    "\033[1;33m",  # bold yellow
    "\033[1;34m",  # bold blue
    "\033[1;35m",  # bold magenta
    "\033[1;36m",  # bold cyan
    "\033[0;91m",  # light red
    "\033[0;92m",  # light green
    "\033[0;93m",  # light yellow
    "\033[0;94m",  # light blue
    "\033[0;95m",  # light magenta
    "\033[0;96m",  # light cyan
]
_RESET = "\033[0m"


def _random_banner() -> str:
    """Return a randomly colored ASCII art banner."""
    art = random.choice(_BANNERS)
    color = random.choice(_COLORS)
    return f"{color}{art}{_RESET}"


class EventMillShell(cmd.Cmd):
    """Interactive Event Mill investigation shell.
    
    Provides a Metasploit-style command interface for managing
    sessions, loading artifacts, selecting pillars, and running tools.
    """
    
    # Intro is set dynamically in preloop() to include startup stats
    intro = ""
    
    def __init__(
        self,
        workspace_path: str | Path | None = None,
        plugins_path: str | Path | None = None,
    ):
        """Initialize Event Mill shell.
        
        Args:
            workspace_path: Path to workspace directory.
            plugins_path: Path to plugins directory.
        """
        super().__init__()
        
        # Determine paths
        self.project_root = Path(__file__).resolve().parent.parent.parent
        self.workspace_path = Path(
            workspace_path or os.environ.get(
                "EVENTMILL_WORKSPACE",
                self.project_root / "workspace",
            )
        )
        self.plugins_path = Path(
            plugins_path or self.project_root / "plugins"
        )
        
        # Initialize components
        self.session_manager = SessionManager(self.workspace_path)
        self.plugin_loader = PluginLoader(self.plugins_path)
        self.llm_client: LLMModelClient | LLMDispatcher | None = None
        self.router: Router | None = None
        self.artifact_registry: ArtifactRegistry | None = None
        self.context_builder = ContextBuilder()
        self._conversation_history: list[dict[str, str]] = []
        self._input_schema_cache: dict[str, dict[str, Any]] = {}
        self._last_file_listing: FileListing | None = None
        
        # Initialize storage resolver
        # In Cloud Run (K_SERVICE set), use GCS resolver; otherwise local
        if os.environ.get("K_SERVICE"):
            try:
                from ..cloud.resolver import create_gcs_resolver
                self.storage_resolver: StorageResolver | None = create_gcs_resolver()
            except Exception as e:
                logger.warning("Failed to create GCS resolver: %s", e)
                self.storage_resolver = None
        else:
            storage_base = self.workspace_path / "storage"
            self.storage_resolver = create_local_resolver(base_path=storage_base)
        
        # Discover plugins and track stats for startup summary
        discovered = self.plugin_loader.discover_all()
        self._plugin_count = len(discovered)
        # Each plugin is one tool in Event Mill's architecture
        self._tool_count = self._plugin_count
        self._load_errors: list[str] = []
        logger.info("Discovered %d plugins", len(discovered))
        
        # Load routing config
        routing_config_dir = (
            self.project_root / "framework" / "routing" / "config"
        )
        if routing_config_dir.exists():
            try:
                config = RouterConfig.load_from_directory(routing_config_dir)
                self.router = Router(self.plugin_loader, config)
                logger.info("Router initialized")
            except Exception as e:
                self._load_errors.append(f"Router: {e}")
                logger.warning("Failed to initialize router: %s", e)
        
        # LLM availability — tiers come from each configured provider's
        # capability manifest (framework/llm/providers/<provider_id>.json), so
        # model ids, API-key env vars, and output caps live in one declarative
        # place per vendor rather than in the shell.
        self._provider_specs = self._load_provider_specs()
        self._tier_specs = self._provider_specs.get(DEFAULT_PROVIDER_ID, {})
        self._available_models: list[dict[str, str]] = self._discover_models()
        self._llm_available = len(self._available_models) > 0

        # Which vendor serves what, chosen by the operator with 'use'. Not
        # persisted: an A/B selection surviving a restart invisibly is the same
        # hazard as a stale .env pin. None means the dispatcher's own default.
        self._provider_default: str | None = None
        self._provider_by_tool: dict[str, str] = {}
        
        self._update_prompt()
    
    _TIER_DISPLAY = {"light": "light (fast, cheap)", "heavy": "heavy (deep reasoning)"}

    def _load_provider_specs(self) -> dict[str, dict[str, TierSpec]]:
        """Tier specs for every provider this session is configured to use.

        EVENTMILL_LLM_PROVIDERS names them; a mounted key does not. An unknown
        id there is an operator typo that must not stop the shell from
        starting, so it is recorded as a load error and the session falls back
        to the default provider alone.
        """
        try:
            configured = llm_factory.configured_providers()
        except llm_factory.UnknownProviderError as e:
            self._load_errors.append(f"LLM providers: {e}")
            logger.warning("Falling back to %s alone: %s", DEFAULT_PROVIDER_ID, e)
            configured = (DEFAULT_PROVIDER_ID,)
        return {
            provider_id: load_tier_specs(provider_id)
            for provider_id in configured
        }

    def _build_client(
        self, model: dict[str, str], failures: list[str],
    ) -> LLMModelClient | None:
        """Build and connect one tier's client, or record why it could not.

        The class comes from the provider registry rather than being named
        here, so adding a vendor stays a registry entry plus a manifest.
        connect() makes no network call on any provider — it builds an SDK
        handle — so success here means the key was present, not that it works.
        'providers probe' is what answers reachability.
        """
        provider_id = model.get("provider", DEFAULT_PROVIDER_ID)
        api_key = (os.environ.get(model["env_var"]) or "").strip()
        if not api_key or api_key == llm_factory.PLACEHOLDER:
            failures.append(
                f"  ✗ {model['name']}: {model['env_var']} unset or placeholder"
            )
            return None
        try:
            cls = llm_factory.client_class(provider_id)
        except ImportError as e:
            target = llm_factory.sdk_install_target(provider_id)
            failures.append(
                f"  ✗ {model['name']}: {provider_id} SDK not installed ({e}) — "
                f"pip install '{target}'"
            )
            return None
        except llm_factory.UnknownProviderError as e:
            failures.append(f"  ✗ {model['name']}: {e}")
            return None

        client = cls(
            model_id=model["id"],
            tier=model["tier"],
            api_key_env_var=model["env_var"],
            provider_id=provider_id,
        )
        if not client.connect(api_key=api_key):
            failures.append(
                f"  ✗ {model['name']}: connect failed for {provider_id} — "
                f"check the key in {model['env_var']}"
            )
            return None
        return client

    def _report_dormant_providers(
        self, clients: dict[tuple[str, str], LLMModelClient],
    ) -> None:
        """Name every configured provider that bound nothing, and why.

        Every provider is configured by default, so a vendor whose key is
        absent or still holds the placeholder is the expected steady state
        rather than a fault — but it must not be *invisible*. A key that
        arrived and a key that did not look identical from the outside until
        something asks for that vendor, and that is the failure this project
        has now had three times.
        """
        bound = {provider_id for provider_id, _ in clients}
        dormant: list[tuple[str, tuple[str, ...]]] = []
        for provider_id in self._provider_specs:
            if provider_id in bound:
                continue
            gaps = llm_factory.missing_keys(provider_id)
            if gaps:
                dormant.append((provider_id, gaps))

        if not dormant:
            return
        print("")
        for provider_id, gaps in dormant:
            print(f"  · {provider_id}: dormant — {', '.join(gaps)} "
                  f"unset or placeholder")
        print("    Set a key and reconnect to bind one; no redeploy needed.")
        print("    'providers probe <id>' verifies a key before adopting it.")

    def _bound_tier_specs(
        self, clients: dict[tuple[str, str], LLMModelClient],
    ) -> dict[tuple[str, str], TierSpec] | None:
        """Tier specs keyed the way the client map is.

        Passing a tier-keyed map here would be wrong with two vendors bound:
        the dispatcher fans a tier-keyed spec dict across every bound
        provider, which is right for one vendor and would otherwise price
        Anthropic's 128,000-token output cap off Gemini's 65,536. None means
        'load your own', which is the dispatcher's per-provider path.
        """
        specs: dict[tuple[str, str], TierSpec] = {}
        for provider_id, tier in clients:
            spec = self._provider_specs.get(provider_id, {}).get(tier)
            if spec is not None:
                specs[(provider_id, tier)] = spec
        return specs or None

    def _provider_for(self, tool_name: str) -> str | None:
        """The provider the operator selected for this tool, if any.

        Per-tool override, then session default, then None — and None keeps
        meaning "whatever the dispatcher chose", so a single-vendor session
        behaves exactly as it did before 'use' existed.
        """
        return self._provider_by_tool.get(tool_name) or self._provider_default

    def _provider_kwargs(self, provider_id: str | None) -> dict[str, str]:
        """Provider scope for a direct dispatcher call, if it accepts one.

        Duck-typed the same way TierScopedLLMClient does it, so a bare client
        or a test fake whose query methods take no provider still works.
        """
        if not provider_id:
            return {}
        if not getattr(self.llm_client, "accepts_provider_scope", False):
            return {}
        return {"provider": provider_id}

    def _bound_providers(self) -> tuple[str, ...]:
        """Providers bound for tool execution, or () when nothing is connected."""
        lister = getattr(self.llm_client, "bound_providers", None)
        return tuple(lister()) if lister else ()

    def _prune_provider_selection(self) -> None:
        """Drop selections naming a provider this connect did not bind.

        Reconnecting with a different EVENTMILL_LLM_PROVIDERS would otherwise
        leave an override pointing at an unbound vendor, and the tool would
        fail at its first LLM call rather than at the moment the selection
        stopped being true.
        """
        bound = self._bound_providers()
        if self._provider_default and self._provider_default not in bound:
            print(f"  Cleared 'use {self._provider_default}' — no longer bound.")
            self._provider_default = None
        for tool_name, provider_id in list(self._provider_by_tool.items()):
            if provider_id not in bound:
                del self._provider_by_tool[tool_name]
                print(
                    f"  Cleared the {provider_id} override on {tool_name} — "
                    f"no longer bound."
                )

    def _provider_note(self, will_use_llm: bool, selected: str | None) -> str:
        """' on <provider>' when which vendor serves a run is not obvious.

        Silent for a single-vendor session, so its output is unchanged; loud as
        soon as a choice exists, because the transcript of a three-vendor
        comparison has to say which vendor produced each line.
        """
        if not will_use_llm:
            return ""
        effective = selected or getattr(self.llm_client, "default_provider", None)
        if not effective:
            return ""
        if selected or len(self._bound_providers()) > 1:
            return f" on {effective}"
        return ""

    def _discover_models(self) -> list[dict[str, str]]:
        """Build the available-model list from the provider manifests + environment.

        A tier is available when its declared API-key env var holds something
        other than the placeholder every deployment mounts for a vendor nobody
        has adopted. Providers are listed in the order
        EVENTMILL_LLM_PROVIDERS names them, so the first one bound is the
        session default.

        Falls back to the legacy single GEMINI_API_KEY, which is bound to BOTH
        Gemini tiers so plugin manifests keep driving model selection rather
        than every tool collapsing onto Flash. That fallback is Gemini-only:
        no other vendor ever read that variable.

        One key may reach Flash but not the Pro preview. That binds cleanly —
        connect() does no entitlement check on any provider — and surfaces as
        PERMISSION_DENIED on first use, which LLMDispatcher._is_access_error
        catches and falls back to the other tier of the same provider.
        """
        models: list[dict[str, str]] = []

        for provider_id, specs in self._provider_specs.items():
            for tier in ("light", "heavy"):
                spec = specs.get(tier)
                if not spec or not spec.api_key_env:
                    continue
                key = (os.environ.get(spec.api_key_env) or "").strip()
                if not key or key == llm_factory.PLACEHOLDER:
                    continue
                models.append({
                    "id": spec.model_id,
                    "name": spec.label(),
                    "tier": tier,
                    "env_var": spec.api_key_env,
                    "provider": provider_id,
                })

        legacy_key = (os.environ.get("GEMINI_API_KEY") or "").strip()
        if (
            not models
            and DEFAULT_PROVIDER_ID in self._provider_specs
            and legacy_key
            and legacy_key != llm_factory.PLACEHOLDER
        ):
            # Legacy single-key setup. Bind it to both tiers — one key reaches
            # both models, so plugin manifests still drive model selection
            # instead of everything collapsing onto Flash.
            for tier in ("light", "heavy"):
                spec = self._tier_specs.get(tier)
                if not spec:
                    continue
                models.append({
                    "id": spec.model_id,
                    "name": spec.label(),
                    "tier": tier,
                    "env_var": "GEMINI_API_KEY",
                    "provider": DEFAULT_PROVIDER_ID,
                })
            if not models:
                models.append({
                    "id": "gemini-3.8-flash",
                    "name": "Gemini (default)",
                    "tier": "light",
                    "env_var": "GEMINI_API_KEY",
                    "provider": DEFAULT_PROVIDER_ID,
                })

        return models

    def _update_prompt(self) -> None:
        """Update the command prompt based on current state."""
        session = self.session_manager.get_current_session()
        if session:
            pillar = session.active_pillar or "no-pillar"
            workspace = session.workspace_folder
            if workspace:
                self.prompt = f"eventmill ({pillar}:{workspace}) > "
            else:
                self.prompt = f"eventmill ({pillar}) > "
        else:
            self.prompt = "eventmill > "
    
    def preloop(self) -> None:
        """Display startup banner with summary stats."""
        # Every complete_* method parses 'line'/'text' assuming a token is a
        # whitespace-delimited chunk (e.g. '--fast', 'plugins/net'). readline's
        # own default word-break characters include '-', '/', '.' and more, so
        # without this it silently hands completers the tail end of the token
        # instead — 'run tool --f<TAB>' resolves 'f' against '--fast' and
        # never matches, exactly like nothing was typed being offered instead
        # of completed. Narrowing delims to whitespace makes readline's idea
        # of a word match what every completer already assumes.
        try:
            import readline
            readline.set_completer_delims(" \t\n")
        except ImportError:
            pass  # no readline (e.g. Windows without pyreadline3) — completion is inert anyway

        # Random colored ASCII art banner (Metasploit-style)
        print(_random_banner())
        
        # Build startup summary
        lines = []
        
        # Plugin/tool summary
        if self._load_errors:
            lines.append(f"  ⚠ Loaded {self._plugin_count} plugins, {self._tool_count} tools ({len(self._load_errors)} errors)")
            for err in self._load_errors:
                lines.append(f"    - {err}")
        else:
            lines.append(f"  ✓ Loaded {self._plugin_count} plugins, {self._tool_count} tools")
        
        # LLM availability
        if self._llm_available:
            model_names = [m["name"] for m in self._available_models]
            lines.append(f"  ✓ LLM models available: {', '.join(model_names)}")
        else:
            lines.append("  ○ No LLM configured (set GEMINI_FLASH_API_KEY or GEMINI_PRO_API_KEY)")
        
        lines.append("")
        lines.append("  Type 'help' for available commands, 'new' to start a session.")
        lines.append("")
        
        print("\n".join(lines))
        
        # Log startup activity
        log_user_activity("shell_started", {
            "plugins_loaded": self._plugin_count,
            "tools_loaded": self._tool_count,
            "errors": len(self._load_errors),
            "llm_available": self._llm_available,
        })
    
    # -------------------------------------------------------------------
    # Session Commands
    # -------------------------------------------------------------------
    
    def do_new(self, arg: str) -> None:
        """Create a new investigation session.
        
        Usage: new [description]
        """
        description = arg.strip() if arg else ""
        session = self.session_manager.new_session(description=description)
        self._conversation_history.clear()
        
        # Initialize artifact registry for session
        self.artifact_registry = ArtifactRegistry(
            artifacts_path=self.workspace_path / "artifacts",
            session_id=session.session_id,
        )
        
        # Update user context for activity logging
        set_user_context(session_id=session.session_id)
        
        # Log activity
        log_user_activity("new_session", {
            "session_id": session.session_id,
            "description": description or None,
        })
        
        print(f"  Created session: {session.session_id}")
        if description:
            print(f"  Description: {description}")
        self._update_prompt()
    
    def do_load_session(self, arg: str) -> None:
        """Load an existing session.
        
        Usage: load_session <session_id>
        """
        session_id = arg.strip()
        if not session_id:
            print("  Usage: load_session <session_id>")
            return
        
        session = self.session_manager.load_session(session_id)
        if session:
            self._conversation_history.clear()
            # Initialize artifact registry
            self.artifact_registry = ArtifactRegistry(
                artifacts_path=self.workspace_path / "artifacts",
                session_id=session.session_id,
            )
            # Load existing artifacts from database
            artifacts = self.session_manager.list_artifacts()
            self.artifact_registry.load_from_database(artifacts)
            
            # Update user context for activity logging
            set_user_context(session_id=session.session_id)
            
            # Log activity
            log_user_activity("load_session", {
                "session_id": session.session_id,
                "pillar": session.active_pillar,
            })
            
            print(f"  Loaded session: {session.session_id}")
            print(f"  Pillar: {session.active_pillar or 'none'}")
        else:
            print(f"  Session not found: {session_id}")
        self._update_prompt()
    
    def do_sessions(self, arg: str) -> None:
        """List all sessions.
        
        Usage: sessions
        """
        sessions = self.session_manager.list_sessions()
        if not sessions:
            print("  No sessions found.")
            return
        
        current = self.session_manager.get_current_session()
        print(f"  {'':2s} {'Session ID':20s} {'Pillar':20s} {'Updated':20s} Description")
        print(f"  {'':2s} {'─' * 20} {'─' * 20} {'─' * 20} {'─' * 20}")
        
        for s in sessions:
            marker = "▸ " if current and s.session_id == current.session_id else "  "
            pillar = s.active_pillar or "—"
            updated = s.updated_at.strftime("%Y-%m-%d %H:%M")
            desc = s.description[:30] if s.description else "—"
            print(f"  {marker}{s.session_id:20s} {pillar:20s} {updated:20s} {desc}")
    
    def do_delete_session(self, arg: str) -> None:
        """Delete a session.
        
        Usage: delete_session <session_id>
        """
        session_id = arg.strip()
        if not session_id:
            print("  Usage: delete_session <session_id>")
            return
        
        self.session_manager.delete_session(session_id)
        
        # Log activity
        log_user_activity("delete_session", {"session_id": session_id})
        
        print(f"  Deleted session: {session_id}")
        self._update_prompt()
    
    # -------------------------------------------------------------------
    # Pillar Commands
    # -------------------------------------------------------------------
    
    def do_pillar(self, arg: str) -> None:
        """Set or show the active investigation pillar.
        
        Usage: pillar [pillar_name]
        
        Available pillars: log_analysis, network_forensics,
        threat_modeling, cloud_investigation, risk_assessment
        """
        if not self.session_manager.get_current_session():
            print("  No active session. Use 'new' to create one.")
            return
        
        pillar = arg.strip()
        if not pillar:
            # Show current pillar
            session = self.session_manager.get_current_session()
            if session.active_pillar:
                print(f"  Active pillar: {session.active_pillar}")
                
                # Show tools for this pillar
                tools = self.plugin_loader.get_by_pillar(session.active_pillar)
                if tools:
                    print(f"  Available tools ({len(tools)}):")
                    for tool in tools:
                        print(
                            f"    - {tool.manifest.display_name} "
                            f"({tool.tool_name})"
                        )
            else:
                print("  No pillar selected. Available pillars:")
                for p in sorted(Pillar.ALL):
                    count = len(self.plugin_loader.get_by_pillar(p))
                    print(f"    - {p} ({count} tools)")
            return
        
        if not Pillar.is_valid(pillar):
            print(f"  Invalid pillar: {pillar}")
            print(f"  Valid pillars: {', '.join(sorted(Pillar.ALL))}")
            return
        
        self.session_manager.set_pillar(pillar)
        tools = self.plugin_loader.get_by_pillar(pillar)
        
        # Log activity
        log_user_activity("set_pillar", {
            "pillar": pillar,
            "tools_available": len(tools),
        })
        
        print(f"  Pillar set to: {pillar} ({len(tools)} tools available)")
        self._update_prompt()

    def complete_pillar(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return [p for p in sorted(Pillar.ALL) if p.startswith(text)]

    # -------------------------------------------------------------------
    # Workspace Commands
    # -------------------------------------------------------------------
    
    def do_workspace(self, arg: str) -> None:
        """Set or show the active workspace folder.
        
        The workspace folder scopes file resolution to a subfolder within
        each storage bucket (e.g. an incident identifier).
        
        Usage:
            workspace                  — show current workspace
            workspace <folder_name>    — set workspace folder
            workspace clear            — clear workspace folder
        """
        if not self.session_manager.get_current_session():
            print("  No active session. Use 'new' to create one.")
            return
        
        folder = arg.strip()
        
        if not folder:
            # Show current workspace
            session = self.session_manager.get_current_session()
            if session.workspace_folder:
                print(f"  Workspace: {session.workspace_folder}")
            else:
                print("  No workspace folder set.")
                print("  Usage: workspace <folder_name>  (e.g. workspace incident-2024-03)")
            return
        
        if folder == "clear":
            self.session_manager.set_workspace(None)
            log_user_activity("clear_workspace")
            print("  Workspace folder cleared.")
        else:
            self.session_manager.set_workspace(folder)
            log_user_activity("set_workspace", {"workspace_folder": folder})
            print(f"  Workspace set to: {folder}")
        
        self._update_prompt()
    
    def do_buckets(self, arg: str) -> None:
        """Show configured storage buckets.
        
        Usage: buckets
        """
        if not self.storage_resolver:
            print("  Storage resolver not initialized.")
            return
        
        buckets = self.storage_resolver.describe_buckets()
        
        print(f"  {'Pillar':25s} {'Bucket':40s} Type")
        print(f"  {'─' * 25} {'─' * 40} {'─' * 10}")
        
        for b in buckets:
            print(f"  {b['pillar']:25s} {b['bucket']:40s} {b['type']}")

    # Tools whose outputs are exported to the common bucket automatically
    # after each run when the shell is on Cloud Run (or EVENTMILL_AUTO_EXPORT=1).
    # Override with EVENTMILL_AUTO_EXPORT_TOOLS ("*" = every tool, "" = none).
    DEFAULT_AUTO_EXPORT_TOOLS = "attack_path_visualizer"

    def do_export(self, arg: str) -> None:
        """Export session artifacts to the common storage bucket.

        Writes to common/exports/<source_tool>/ by default — mirroring the
        common/generated/ convention used by threat_report_analyzer.  On Cloud
        Run this is the durable copy: the container's workspace/artifacts is
        ephemeral and disappears when the instance is recycled.

        Usage: export <artifact_id> [subfolder]
               export --all [subfolder]

        artifact_id — ID from the 'artifacts' command (e.g. art_04d30b48)
        --all       — Export every tool-produced artifact in the session
                      (inputs you loaded from a bucket are skipped; they are
                      already there).
        subfolder   — Optional path appended inside exports/<source_tool>/.
                      Useful for tagging by incident (e.g. incident-2025-04).

        Destination layout:
          common/exports/<source_tool>/<filename>
          common/exports/<source_tool>/<subfolder>/<filename>   (with subfolder)

        Examples:
          export art_04d30b48
          export art_04d30b48 incident-2025-04
          export --all crowdstrike-2026

        On Cloud Run, attack_path_visualizer outputs are exported automatically
        after each run (see EVENTMILL_AUTO_EXPORT_TOOLS).
        """
        if not self.session_manager.get_current_session():
            print("  No active session. Use 'session new' first.")
            return
        if not self.storage_resolver:
            print("  Storage resolver not initialized.")
            return

        parts = shlex.split(arg) if arg.strip() else []
        if not parts:
            print("  Usage: export <artifact_id> [subfolder]  |  export --all [subfolder]")
            return

        if parts[0] == "--all":
            subfolder = parts[1] if len(parts) > 1 else None
            self._export_all(subfolder)
            return

        artifact_id = parts[0]
        subfolder = parts[1] if len(parts) > 1 else None

        artifact = self.session_manager.get_artifact(artifact_id)
        if artifact is None:
            print(f"  Artifact '{artifact_id}' not found. Use 'artifacts' to list.")
            return
        print(f"  Exporting {artifact_id} ({artifact.artifact_type})")
        self._export_artifact(artifact, subfolder)

    def _export_all(self, subfolder: str | None) -> None:
        """Export every tool-produced artifact in the session."""
        artifacts = self.session_manager.list_artifacts()
        produced = [a for a in artifacts if getattr(a, "source_tool", None)]
        skipped_inputs = len(artifacts) - len(produced)
        if not produced:
            print("  No tool-produced artifacts to export.")
            if skipped_inputs:
                print(f"  ({skipped_inputs} loaded input(s) skipped — already in a bucket.)")
            return

        print(f"  Exporting {len(produced)} tool-produced artifact(s)"
              + (f" to subfolder '{subfolder}'" if subfolder else "") + " ...")
        ok = 0
        for a in produced:
            print(f"  {a.artifact_id} ({a.artifact_type}, {a.source_tool})")
            if self._export_artifact(a, subfolder, indent="    "):
                ok += 1
        print(f"  Exported {ok}/{len(produced)}."
              + (f" {skipped_inputs} loaded input(s) skipped." if skipped_inputs else ""))

    def _export_artifact(
        self, artifact: Any, subfolder: str | None, indent: str = "  "
    ) -> str | None:
        """Upload one artifact to common/exports/<source_tool>[/<subfolder>]/.

        Returns the destination URI, or None if the export did not happen.
        """
        local_path = Path(artifact.file_path)
        if not local_path.exists():
            print(f"{indent}✗ Artifact file missing on disk: {local_path}")
            return None

        source_tool = getattr(artifact, "source_tool", None) or "unknown"
        dest_folder = f"exports/{source_tool}"
        if subfolder:
            dest_folder = f"{dest_folder}/{subfolder}"

        # Pillar is only needed by the resolver to name the pillar bucket;
        # since target="common" it won't be used for routing, but must be valid.
        session = self.session_manager.get_current_session()
        pillar = session.active_pillar or "log_analysis"
        filename = local_path.name
        common_bucket = self.storage_resolver.config.common_bucket()
        print(f"{indent}Destination: {common_bucket}/{dest_folder}/{filename}")
        try:
            resolved = self.storage_resolver.upload(
                local_path=local_path,
                filename=filename,
                pillar=pillar,
                workspace_folder=dest_folder,
                target="common",
                metadata={
                    "artifact_id": artifact.artifact_id,
                    "artifact_type": artifact.artifact_type,
                    "source_tool": source_tool,
                },
            )
            print(f"{indent}✓ Uploaded: {resolved.uri}")
            log_user_activity("export_artifact", {
                "artifact_id": artifact.artifact_id,
                "destination": resolved.uri,
                "source_tool": source_tool,
            })
            return resolved.uri
        except Exception as e:
            print(f"{indent}✗ Export failed: {e}")
            logger.error("Artifact export failed: %s", e)
            return None

    def _auto_export_enabled(self, tool_name: str) -> bool:
        """Auto-export runs on Cloud Run (K_SERVICE) or when EVENTMILL_AUTO_EXPORT=1,
        for the tools named in EVENTMILL_AUTO_EXPORT_TOOLS."""
        on_cloud_run = bool(os.environ.get("K_SERVICE"))
        forced = os.environ.get("EVENTMILL_AUTO_EXPORT", "") == "1"
        if not (on_cloud_run or forced):
            return False
        raw = os.environ.get("EVENTMILL_AUTO_EXPORT_TOOLS")
        if raw is None:
            raw = self.DEFAULT_AUTO_EXPORT_TOOLS
        tools = {t.strip() for t in raw.split(",") if t.strip()}
        return "*" in tools or tool_name in tools

    def _auto_export_run_output(self, tool_name: str, artifacts_before: set[str]) -> None:
        """Push the artifacts a run just produced to the common bucket.

        Only for tools selected by _auto_export_enabled.  Failures are
        reported but never fail the run — the files are still on disk and
        can be exported by hand.
        """
        if not self._auto_export_enabled(tool_name):
            return
        new_artifacts = [
            a for a in self.session_manager.list_artifacts()
            if a.artifact_id not in artifacts_before
        ]
        if not new_artifacts:
            return
        if not self.storage_resolver:
            print("  Auto-export skipped: storage resolver not initialized.")
            return
        print(f"\n  Auto-export ({len(new_artifacts)} file(s) to the common bucket):")
        for a in new_artifacts:
            self._export_artifact(a, None, indent="    ")

    def do_files(self, arg: str) -> None:
        """List files the current pillar can see.

        Lists the pillar's own bucket by default. The common bucket holds
        shared reference data plus tool output under exports/ and generated/;
        it is one flag away, and the footer says how much is over there.

        Usage: files [--source pillar|common|all] [--folders]
                     [--path <folder>] [--ext .log,.json] [--newer 24h]
                     [--match <pattern>] [--sort time|size|name] [--limit N]

        Scope:
          --source  pillar (default), common, or all
          --folders show the folder layout instead of the files
          --path    a folder inside the bucket, e.g. reports or
                    vendor_advisories. Not a pillar or bucket name — the
                    pillar you are in already picks the bucket.

        Filters:
          --ext     comma-separated extensions; matches any suffix, so
                    --ext .log also matches auth.log.1
          --newer   files modified within a duration: 90m, 24h, 7d, 2w
          --match   substring on the path, or a glob when it contains * or ?

        Display:
          --sort    time (newest first, default), size (largest first), name
          --limit   rows to show, default 50; --limit 0 shows all

        Rows are numbered. Use #N in place of a path:

          files --folders
          files --ext .log --newer 24h
          load #2
          run log_navigator --action read --path #2
        """
        session = self.session_manager.get_current_session()
        if not session:
            print("  No active session. Use 'new' to create one.")
            return

        if not session.active_pillar:
            print("  No pillar selected. Use 'pillar <name>' first.")
            return

        if not self.storage_resolver:
            print("  Storage resolver not initialized.")
            return

        query = self._parse_files_flags(arg)
        if query is None:
            return

        listing = self.storage_resolver.list_workspace(
            pillar=session.active_pillar,
            workspace_folder=session.workspace_folder,
            prefix=query.prefix,
        )

        location = session.active_pillar
        if session.workspace_folder:
            location += f"/{session.workspace_folder}"

        in_scope = [
            f for f in listing.files if query.source in ("all", f.source)
        ]
        if not in_scope:
            self._explain_empty_listing(listing.files, query, session)
            return

        if query.folders:
            self._render_folder_map(in_scope, query, session.active_pillar)
            return

        matched = self._apply_files_filters(in_scope, query)
        if not matched:
            print(f"  No files in {location} match those filters.")
            print(f"  {len(in_scope)} file(s) before filtering.")
            self._render_source_footer(listing.files, query)
            return

        shown = matched if query.limit == 0 else matched[: query.limit]
        entries = [
            FileListingEntry(index=i, file=f) for i, f in enumerate(shown, start=1)
        ]

        self._last_file_listing = FileListing(
            session_id=session.session_id,
            pillar=session.active_pillar,
            workspace_folder=session.workspace_folder,
            entries=entries,
        )

        self._render_file_table(entries, len(matched), listing.truncated)
        self._render_source_footer(listing.files, query)

    def _parse_files_flags(self, arg: str) -> FilesQuery | None:
        """Parse flags for 'files'. Returns None after printing on error."""
        query = FilesQuery()
        if not arg.strip():
            return query

        try:
            tokens = shlex.split(arg.strip())
        except ValueError as e:
            print(f"  Could not parse arguments: {e}")
            return None

        pairs, error = _split_flags(tokens)
        if error:
            print(f"  {error}")
            return None

        for key, value in pairs:
            if key == "folders":
                if value is not True:
                    print("  --folders takes no value.")
                    return None
                query.folders = True
                continue

            if value is True and key not in ("help",):
                print(f"  --{key} needs a value.")
                return None

            if key == "path":
                query.prefix = str(value).replace("\\", "/").lstrip("/")
            elif key == "source":
                if str(value) not in FILES_SOURCES:
                    print(f"  Unknown --source {value!r}.")
                    print("  Use pillar (default), common, or all.")
                    return None
                query.source = str(value)
            elif key == "ext":
                query.extensions = [
                    "." + part.strip().lstrip(".").lower()
                    for part in str(value).split(",")
                    if part.strip()
                ]
                if not query.extensions:
                    print("  --ext needs at least one extension.")
                    return None
            elif key == "newer":
                delta = _parse_duration(str(value))
                if delta is None:
                    print(f"  Could not read --newer {value!r}.")
                    print("  Use a count and a unit: 90m, 24h, 7d, 2w.")
                    return None
                query.newer_than = delta
            elif key == "match":
                query.match = str(value)
            elif key == "sort":
                if str(value) not in ("time", "size", "name"):
                    print(f"  Unknown --sort {value!r}. Use time, size, or name.")
                    return None
                query.sort = str(value)
            elif key == "limit":
                try:
                    limit = int(str(value))
                except ValueError:
                    print(f"  --limit needs a whole number, got {value!r}.")
                    return None
                if limit < 0:
                    print("  --limit cannot be negative. Use 0 to show all.")
                    return None
                query.limit = limit
            else:
                print(f"  Unknown flag --{key}.")
                print("  Use --source, --folders, --path, --ext, --newer,")
                print("  --match, --sort, --limit.")
                return None

        return query

    def _apply_files_filters(
        self,
        files: list[WorkspaceFile],
        query: FilesQuery,
    ) -> list[WorkspaceFile]:
        """Apply the shell-side filters and ordering to a listing."""
        cutoff = (
            datetime.now(timezone.utc) - query.newer_than
            if query.newer_than
            else None
        )
        is_glob = any(ch in query.match for ch in "*?")
        needle = query.match.lower()

        matched: list[WorkspaceFile] = []
        for f in files:
            if query.extensions:
                suffixes = [s.lower() for s in Path(f.filename).suffixes]
                if not any(ext in suffixes for ext in query.extensions):
                    continue
            if cutoff is not None:
                if f.modified is None:
                    continue
                moment = f.modified
                if moment.tzinfo is None:
                    moment = moment.replace(tzinfo=timezone.utc)
                if moment < cutoff:
                    continue
            if query.match:
                if is_glob:
                    if not fnmatch.fnmatch(f.object_path.lower(), needle):
                        continue
                elif needle not in f.object_path.lower():
                    continue
            matched.append(f)

        # Unknown size/mtime sorts last so a degraded backend stays ordered
        if query.sort == "time":
            matched.sort(key=lambda f: f.object_path)
            matched.sort(
                key=lambda f: (
                    f.modified is None,
                    -(f.modified.timestamp() if f.modified else 0),
                )
            )
        elif query.sort == "size":
            matched.sort(key=lambda f: f.object_path)
            matched.sort(
                key=lambda f: (f.size_bytes is None, -(f.size_bytes or 0))
            )
        else:
            matched.sort(key=lambda f: f.object_path)

        return matched

    def _render_folder_map(
        self,
        files: list[WorkspaceFile],
        query: FilesQuery,
        pillar: str,
    ) -> None:
        """Print the folder layout instead of the files themselves.

        Nothing else in the shell shows how storage is laid out, so an
        analyst who has never seen the buckets has no way to guess what to
        pass to --path. This is that map, one level at a time.
        """
        config = self.storage_resolver.config
        buckets = [
            ("pillar", config.bucket_for_pillar(pillar)),
            ("common", config.common_bucket()),
        ]
        here = query.prefix.rstrip("/")
        where = f"under {here}/" if here else "at the top level"
        print(f"  Folders {where}, as seen from the {pillar} pillar:")
        print()

        drillable = False
        for source, bucket in buckets:
            if query.source not in ("all", source):
                continue
            group = [f for f in files if f.source == source]
            if not group:
                continue
            print(f"  {source} bucket — {bucket}")
            for label, count, size in _folder_breakdown(group, here):
                drillable = drillable or label != FOLDER_LEAF
                noun = "file" if count == 1 else "files"
                counted = f"{count} {noun}"
                print(f"    {label:<36s} {counted:>9s}  {_format_bytes(size)}")
            print()

        scoped = f" --path {here}" if here else ""
        scope = "" if query.source == "pillar" else f" --source {query.source}"
        if drillable:
            print(f"  Drill in with:   files --path <folder>{scope} --folders")
            print(f"  List the files:  files --path <folder>{scope}")
        else:
            print("  No folders below this one.")
            print(f"  List what is here: files{scoped}{scope}")

    def _render_source_footer(
        self,
        all_files: list[WorkspaceFile],
        query: FilesQuery,
    ) -> None:
        """Name what --source is holding back, and how to see it.

        Listing the pillar alone is the useful default, but only if it never
        looks like the whole picture — so a listing that hid files says how
        many and where.
        """
        if query.source == "all":
            return

        other = "common" if query.source == "pillar" else "pillar"
        hidden = self._apply_files_filters(
            [f for f in all_files if f.source == other], query
        )
        if not hidden:
            return

        folders = [label for label, _, _ in _folder_breakdown(hidden, query.prefix)]
        where = ", ".join(folders[:3])
        if len(folders) > 3:
            where += ", ..."
        noun = "file" if len(hidden) == 1 else "files"
        print(f"  {len(hidden)} more {noun} in the {other} bucket: {where}")
        print("  Add --source all to include them.")

    def _explain_empty_listing(
        self,
        listed: list[WorkspaceFile],
        query: FilesQuery,
        session: Any,
    ) -> None:
        """Say why a listing came back empty and point at what does exist.

        Bucket names and folder layout are not something an analyst is
        expected to know, so an empty result names where it looked rather
        than only reporting that it found nothing.
        """
        pillar = session.active_pillar
        tail = " --folders" if query.folders else ""
        scope = {
            "pillar": f"the {pillar} pillar bucket",
            "common": "the common bucket",
            "all": f"{pillar} or the common bucket",
        }[query.source]

        nothing = "Nothing" if query.folders else "No files"
        if query.prefix:
            print(f"  {nothing} under '{query.prefix}' in {scope}.")
            hint = self._explain_prefix(query.prefix, pillar, tail)
            if hint:
                for line in hint:
                    print(f"  {line}")
                return
        else:
            print(f"  {nothing} in {scope}.")

        # A prefix is applied by the backend, so the listing we were handed
        # cannot say what else is there. Re-list without it.
        if query.prefix:
            probe = self.storage_resolver.list_workspace(
                pillar=pillar,
                workspace_folder=session.workspace_folder,
            ).files
        else:
            probe = listed

        if not probe:
            print("  Nothing at all is visible from this pillar. If files are")
            print("  expected, check that the deployment's bucket prefix")
            print("  matches this project: use 'status' to see the buckets.")
            return

        if query.source != "all":
            elsewhere = self._apply_files_filters(
                [
                    f for f in probe
                    if f.source != query.source
                    and f.object_path.startswith(query.prefix)
                ],
                query,
            )
            if elsewhere:
                other = "common" if query.source == "pillar" else "pillar"
                noun = "file" if len(elsewhere) == 1 else "files"
                verb = "matches" if len(elsewhere) == 1 else "match"
                scoped = f" --path {query.prefix}" if query.prefix else ""
                print(f"  {len(elsewhere)} {noun} {verb} in the {other} bucket:")
                print(f"  files{scoped} --source all{tail}")
                return

        folders = [label for label, _, _ in _folder_breakdown(probe)]
        if query.prefix:
            close = difflib.get_close_matches(
                query.prefix.rstrip("/") + "/", folders, n=3, cutoff=0.5
            )
            if close:
                print(f"  Did you mean: {', '.join(close)}")
        print(f"  Folders here: {', '.join(folders[:8])}")
        print("  See the full layout with: files --folders --source all")

    def _explain_prefix(
        self,
        prefix: str,
        pillar: str,
        tail: str = "",
    ) -> list[str] | None:
        """Return an explanation when --path was handed a bucket, not a folder.

        Pillar names never appear in object keys — the pillar selects the
        bucket — so this is the mistake worth naming outright rather than
        answering with an empty listing.
        """
        needle = prefix.strip("/").lower()
        config = self.storage_resolver.config

        own = {pillar.lower(), config.bucket_for_pillar(pillar).lower()}
        own.add(PILLAR_SLUGS.get(pillar, pillar.replace("_", "-")).lower())
        if needle in own:
            return [
                f"'{prefix}' is the bucket you are already in, not a folder",
                "inside it. The pillar picks the bucket; --path picks a folder",
                "below it. Run 'files --folders' to map the folders that exist.",
            ]

        if needle in ("common", config.common_bucket().lower()):
            return [
                f"'{prefix}' is a bucket, not a folder inside one.",
                f"List it with: files --source common{tail}",
            ]

        for other in Pillar.ALL:
            if other == pillar:
                continue
            names = {other.lower(), config.bucket_for_pillar(other).lower()}
            names.add(PILLAR_SLUGS.get(other, other.replace("_", "-")).lower())
            if needle in names:
                return [
                    f"'{prefix}' is a different pillar's bucket, not a folder.",
                    f"Switch to it with: pillar {other}",
                ]

        return None

    def _render_file_table(
        self,
        entries: list[FileListingEntry],
        total: int,
        truncated: bool,
    ) -> None:
        """Print a numbered file listing."""
        print(f"  {'#':>3s}  Path")

        for entry in entries:
            f = entry.file
            size = _format_bytes(f.size_bytes)
            print(f"  {entry.index:>3d}  {f.object_path}")
            print(
                f"       Source: {f.source}  Size: {size}  "
                f"Modified: {_format_age(f.modified)}"
            )
            print()

        hidden = total - len(entries)
        if hidden > 0:
            print(f"\n  ... and {hidden} more. Use --limit 0 to show all.")
        if truncated:
            print("\n  ⚠ Listing hit the per-bucket object cap; filters saw")
            print("    only part of the store. Narrow it with --path <prefix>.")

    def complete_files(
        self,
        text: str,
        line: str,
        begidx: int,
        endidx: int,
    ) -> list[str]:
        """Complete flag names for 'files'."""
        flags = [
            "--source", "--folders", "--path", "--ext",
            "--newer", "--match", "--sort", "--limit",
        ]
        return [f for f in flags if f.startswith(text)]

    def _resolve_file_ref(self, ref: str) -> FileListingEntry | None:
        """Look up a '#N' reference against the last 'files' listing.

        Returns None after printing why when there is no listing, the
        listing was taken elsewhere, or the index is out of range.
        """
        match = _FILE_REF_RE.match(ref)
        if not match:
            return None

        listing = self._last_file_listing
        if listing is None:
            print(f"  No file listing to resolve {ref} against. Run 'files' first.")
            return None

        session = self.session_manager.get_current_session()
        if not session:
            print("  No active session.")
            return None

        current = (session.session_id, session.active_pillar, session.workspace_folder)
        taken = (listing.session_id, listing.pillar, listing.workspace_folder)
        if current != taken:
            def label(pillar: str, folder: str | None) -> str:
                return f"{pillar}:{folder}" if folder else str(pillar)

            was = label(listing.pillar, listing.workspace_folder)
            now = label(session.active_pillar, session.workspace_folder)
            print(f"  {ref} was listed under {was};")
            print(f"  you are now in {now}. Run 'files' again.")
            return None

        index = int(match.group(1))
        if index < 1 or index > len(listing.entries):
            print(
                f"  {ref} is out of range; the last listing had "
                f"{len(listing.entries)} row(s)."
            )
            return None

        return listing.entries[index - 1]


    # -------------------------------------------------------------------
    # Artifact Commands
    # -------------------------------------------------------------------

    _LOAD_ARTIFACT_TYPES = (
        "pcap", "json_events", "log_stream", "risk_model",
        "cloud_audit_log", "pdf_report", "html_report", "image", "text",
    )

    def complete_load(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        """Complete 'load': a filesystem path first, then artifact type or --fast.

        No completer existed for this command at all before this — 'load
        capture.pcap --fa' had nothing to complete against, at any position,
        the same gap complete_run had before it grew flag/enum completion.
        """
        parts = line[:begidx].split()
        args_before = parts[1:] if parts and parts[0] == "load" else parts

        if not args_before:
            return self._complete_path(text)

        # After the file path: remaining artifact types, plus --fast/--merge
        # unless already on the line. Order doesn't matter to do_load.
        candidates = [t for t in self._LOAD_ARTIFACT_TYPES if t not in args_before]
        if "--fast" not in args_before:
            candidates.append("--fast")
        if "--merge" not in args_before:
            candidates.append("--merge")
        return [c for c in sorted(candidates) if c.startswith(text)]

    @staticmethod
    def _complete_path(text: str) -> list[str]:
        """Filesystem path completion; directories are suffixed with a separator."""
        directory = os.path.dirname(text) or "."
        prefix = os.path.basename(text)
        try:
            names = os.listdir(directory)
        except OSError:
            return []
        lead = os.path.dirname(text)
        results = []
        for name in sorted(names):
            if not name.startswith(prefix):
                continue
            candidate = os.path.join(lead, name) if lead else name
            if os.path.isdir(os.path.join(directory, name)):
                candidate += os.sep
            results.append(candidate)
        return results

    def do_load(self, arg: str) -> None:
        """Load an artifact file into the current session.
        
        Usage: load <file_path_or_name> [artifact_type] [--fast] [--merge]
               load <folder_path> --merge [--fast]
               load --merge [--fast]
        
        Options:
          --fast     Use dpkt (fast C-backed parser) instead of scapy.
                     Recommended for PCAPs >100 MB / >500K packets.
                     5-10x faster, identical report output.
          --merge    Cumulative load — merge multiple PCAPs into one session.
                     With a folder path: loads all *.pcap/*.pcapng in that folder.
                     With a file: merges into the already-loaded session.
                     Without a path: loads all PCAPs from current workspace location.
        
        Resolution order:
          1. Local file path (if exists on disk)
          2. Explicit gs:// URI
          3. Pillar bucket (workspace folder, then root)
          4. Common bucket (workspace folder, then root)
        
        Supported types: pcap, json_events, log_stream, risk_model,
        cloud_audit_log, pdf_report, html_report, image, text

        Examples:
          load capture.pcap
          load capture.pcap --fast
          load /path/to/folder/ --merge --fast
          load --merge --fast
          load another.pcap --merge
        """
        if not self.session_manager.get_current_session():
            print("  No active session. Use 'new' to create one.")
            return
        
        try:
            parts = shlex.split(arg.strip())
        except ValueError:
            parts = arg.strip().split(maxsplit=1)

        # Check for --fast and --merge flags
        use_dpkt = "--fast" in parts
        merge_mode = "--merge" in parts
        parts = [p for p in parts if p not in ("--fast", "--merge")]

        # --merge with a folder path, a file path, or no path (workspace home)
        if merge_mode:
            self._load_merge(parts, use_dpkt=use_dpkt)
            return

        if not parts:
            print("  Usage: load <file_path_or_name> [artifact_type] [--fast] [--merge]")
            return
        
        file_ref = parts[0]
        listing_entry: FileListingEntry | None = None
        if _FILE_REF_RE.match(file_ref):
            listing_entry = self._resolve_file_ref(file_ref)
            if listing_entry is None:
                return
            # The URI is exact, so this skips re-resolution entirely
            file_ref = listing_entry.file.uri
            print(f"  {parts[0]} → {file_ref}")

        file_path = Path(file_ref)

        # Try local file first
        if file_path.exists():
            artifact_type = parts[1] if len(parts) > 1 else self._infer_artifact_type(file_path)
            artifact_id = self._register_local_artifact(
                file_path, artifact_type, use_dpkt=use_dpkt
            )
            if listing_entry:
                listing_entry.artifact_id = artifact_id
                listing_entry.local_path = file_path
            return
        
        # Try storage resolver (gs:// URI or filename lookup in buckets)
        session = self.session_manager.get_current_session()
        if self.storage_resolver and session.active_pillar:
            explicit = file_ref if file_ref.startswith("gs://") else None
            filename = file_ref if not explicit else None
            
            resolved = self.storage_resolver.resolve(
                filename=filename or "",
                pillar=session.active_pillar,
                workspace_folder=session.workspace_folder,
                explicit_path=explicit,
            )
            
            if resolved:
                # Download to local workspace for tool access
                local_dest = (
                    self.workspace_path / "artifacts"
                    / session.session_id
                    / (resolved.object_path.rsplit("/", 1)[-1] if "/" in resolved.object_path else resolved.object_path)
                )
                local_dest.parent.mkdir(parents=True, exist_ok=True)
                
                try:
                    self.storage_resolver.download(resolved, local_dest)
                except Exception as e:
                    print(f"  Failed to download from {resolved.display}: {e}")
                    return
                
                artifact_type = parts[1] if len(parts) > 1 else self._infer_artifact_type(local_dest)
                artifact_id = self._register_local_artifact(
                    local_dest,
                    artifact_type,
                    source_info=resolved.display,
                    use_dpkt=use_dpkt,
                )
                if listing_entry:
                    listing_entry.artifact_id = artifact_id
                    listing_entry.local_path = local_dest
                return
        
        # Nothing found
        print(f"  File not found: {file_ref}")
        if session.active_pillar and self.storage_resolver:
            print(f"  Searched: local path, {session.active_pillar} bucket, common bucket")
            if session.workspace_folder:
                print(f"  Workspace: {session.workspace_folder}")
        else:
            print("  Tip: set a pillar to enable bucket-based file resolution.")
    
    @staticmethod
    def _artifact_metadata(file_path: Path) -> dict[str, Any]:
        """Metadata captured when a file is loaded.

        The PDF page count is recorded here because it cannot be recovered
        later: once an artifact resolves to GCS there is no local file to
        read, and the dispatcher's context-overflow guard needs it to size
        the request before sending it.
        """
        metadata: dict[str, Any] = {"original_filename": file_path.name}
        try:
            metadata["size_bytes"] = file_path.stat().st_size
        except OSError as e:
            logger.warning("Could not stat %s: %s", file_path, e)

        if file_path.suffix.lower() != ".pdf":
            return metadata

        metadata["mime_type"] = "application/pdf"
        try:
            from pypdf import PdfReader
            metadata["pages"] = len(PdfReader(str(file_path)).pages)
        except Exception as e:
            logger.warning("Could not read page count from %s: %s", file_path, e)
        return metadata

    def _register_local_artifact(
        self,
        file_path: Path,
        artifact_type: str,
        source_info: str | None = None,
        use_dpkt: bool = False,
    ) -> str:
        """Register a local file as an artifact in the current session.

        Returns the new artifact id so callers can associate it with the
        listing row the file came from.
        """
        metadata = self._artifact_metadata(file_path)
        artifact = self.session_manager.register_artifact(
            artifact_type=artifact_type,
            file_path=str(file_path.resolve()),
            metadata=metadata,
        )
        
        if self.artifact_registry:
            self.artifact_registry.register(
                artifact_type=artifact_type,
                source_path=file_path,
                metadata=dict(metadata),
                copy_file=False,
            )
        
        # Log activity
        log_user_activity("load_artifact", {
            "artifact_id": artifact.artifact_id,
            "artifact_type": artifact_type,
            "filename": file_path.name,
        })
        
        print(f"  Loaded artifact: {artifact.artifact_id}")
        print(f"  Type: {artifact_type}")
        print(f"  File: {file_path.name}")
        if source_info:
            print(f"  Source: {source_info}")

        # Auto-parse PCAP files (mirrors event_mill v1 load_pcap behaviour)
        if artifact_type == "pcap":
            self._auto_parse_pcap(file_path, use_dpkt=use_dpkt)

        return artifact.artifact_id

    def _auto_parse_pcap(self, file_path: Path, use_dpkt: bool = False) -> None:
        """Automatically parse a PCAP so downstream tools work immediately.

        Mirrors event_mill v1 where ``load_pcap`` was a single atomic operation.
        Uses the process-global session storage so the loader's module and the
        shell's module see the same PcapSession singleton.

        When use_dpkt=True, uses the fast dpkt parser (5-10x faster for large
        captures). Use ``load file.pcap --fast`` to activate.
        """
        try:
            from plugins.network_forensics.pcap_metadata_summary.tool import (
                parse_pcap_file,
                set_pcap_session,
                _format_bytes,
                _format_duration,
                is_internal,
            )

            if use_dpkt:
                from plugins.network_forensics.pcap_metadata_summary.tool import (
                    parse_pcap_file_dpkt,
                    DPKT_AVAILABLE,
                )
                if not DPKT_AVAILABLE:
                    print("  Warning: dpkt not installed, falling back to scapy.")
                    use_dpkt = False

            parser_name = "dpkt (fast mode)" if use_dpkt else "scapy"
            print(f"  Parsing PCAP with {parser_name}...")
            if use_dpkt:
                session = parse_pcap_file_dpkt(str(file_path))
            else:
                session = parse_pcap_file(str(file_path))
            set_pcap_session(session)

            duration = session.duration_seconds
            internal = sum(1 for ip in session.unique_ips if is_internal(ip))
            external = len(session.unique_ips) - internal

            print(
                f"  ✓ {session.packet_count:,} packets, "
                f"{len(session.unique_ips)} IPs ({internal} internal, {external} external), "
                f"duration {_format_duration(duration)}"
            )
            if session.ot_transactions:
                from collections import Counter as _Counter
                ot_protos = _Counter(t["protocol"] for t in session.ot_transactions)
                ot_summary = ", ".join(f"{p}:{c}" for p, c in ot_protos.most_common(5))
                print(f"  ✓ OT/ICS protocols: {ot_summary}")
            if session.cleartext_creds:
                print(f"  ⚠️  Cleartext credentials detected: {len(session.cleartext_creds)}")
            print(f"  PCAP ready — use 'run pcap_metadata_summary {{\"mode\": \"summary\"}}' or any pcap tool.")
        except ImportError:
            print("  Note: pcap_metadata_summary plugin not available; manual 'run' with mode=load required.")
        except Exception as e:
            print(f"  Warning: auto-parse failed ({e}); use 'run pcap_metadata_summary {{\"mode\": \"load\", \"file_path\": \"{file_path.name}\"}}' manually.")

    def _load_merge(self, parts: list[str], use_dpkt: bool = False) -> None:
        """Load and merge multiple PCAPs into a single cumulative session.

        Handles three cases:
          1. Folder path   — load all *.pcap/*.pcapng in that folder (no subdirs)
          2. Single file   — merge into the already-loaded session
          3. No path       — use current workspace/bucket location
        """
        try:
            from plugins.network_forensics.pcap_metadata_summary.tool import (
                parse_pcap_file,
                get_pcap_session,
                set_pcap_session,
                is_internal,
            )
            if use_dpkt:
                from plugins.network_forensics.pcap_metadata_summary.tool import (
                    parse_pcap_file_dpkt,
                    DPKT_AVAILABLE,
                )
                if not DPKT_AVAILABLE:
                    print("  Warning: dpkt not installed, falling back to scapy.")
                    use_dpkt = False
        except ImportError:
            print("  Error: pcap_metadata_summary plugin not available.")
            return

        PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
        parser_name = "dpkt (fast mode)" if use_dpkt else "scapy"
        parse_fn = parse_pcap_file_dpkt if use_dpkt else parse_pcap_file

        # Determine target path
        if parts:
            target_str = parts[0].rstrip("/")
            target = Path(target_str)
        else:
            # No path — try workspace location from storage resolver
            session = self.session_manager.get_current_session()
            if self.storage_resolver and session and session.active_pillar:
                ws = session.workspace_folder or ""
                print(f"  --merge: searching '{ws or 'bucket root'}' for PCAPs...")
                result = self._merge_resolve_bucket_folder(session, use_dpkt, parse_fn)
                if result is not None:
                    return
            # Fallback: current working directory
            target_str = "."
            target = Path(".")

        # Single file merge — merge into existing session
        if target.is_file():
            if target.suffix.lower() not in PCAP_EXTENSIONS:
                print(f"  Not a PCAP file: {target.name}")
                return
            existing = get_pcap_session()
            if not existing:
                print(f"  No existing session to merge into. Loading as new...")
                self._auto_parse_pcap(target, use_dpkt=use_dpkt)
                return
            print(f"  Merging {target.name} with {parser_name}...")
            new_session = parse_fn(str(target))
            existing.merge_into(new_session)
            print(
                f"  ✓ Merged {new_session.packet_count:,} packets from {target.name}"
            )
            self._print_merge_summary(existing)
            return

        # Folder merge — find all PCAPs in folder (no subdirs)
        if target.is_dir():
            pcap_files = sorted(
                f for f in target.iterdir()
                if f.is_file() and f.suffix.lower() in PCAP_EXTENSIONS
            )
            if not pcap_files:
                print(f"  No PCAP files found in: {target}")
                return

            print(f"  Found {len(pcap_files)} PCAP file(s) in {target}")
            print(f"  Parser: {parser_name}")
            print()

            cumulative = get_pcap_session()
            loaded = 0

            for i, pcap_file in enumerate(pcap_files, 1):
                print(f"  [{i}/{len(pcap_files)}] Parsing {pcap_file.name}...")
                try:
                    new_session = parse_fn(str(pcap_file))
                    if cumulative is None:
                        cumulative = new_session
                    else:
                        cumulative.merge_into(new_session)
                    loaded += 1
                    print(f"    ✓ {new_session.packet_count:,} packets")
                except Exception as e:
                    print(f"    ✗ Failed: {e}")

            if cumulative and loaded > 0:
                set_pcap_session(cumulative)
                print()
                print(f"  Merge complete — {loaded} file(s) loaded")
                self._print_merge_summary(cumulative)
            else:
                print("  No files were successfully parsed.")
            return

        # Not a local file or dir — try bucket resolution
        session = self.session_manager.get_current_session()
        if self.storage_resolver and session and session.active_pillar:
            print(f"  Resolving '{target_str}' from bucket...")
            self._merge_resolve_bucket_folder(session, use_dpkt, parse_fn, target_str)
            return

        print(f"  Path not found: {target}")

    def _merge_resolve_bucket_folder(
        self, session, use_dpkt: bool, parse_fn, prefix: str | None = None
    ):
        """Resolve and merge PCAPs from a bucket folder (GCS or local resolver).

        Returns None if bucket resolution is not available, so the caller
        can fall back to local directory logic.
        """
        from plugins.network_forensics.pcap_metadata_summary.tool import (
            get_pcap_session,
            set_pcap_session,
        )
        PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}

        try:
            # Use prefix as workspace_folder override, or fall back to session's
            folder = prefix.rstrip("/") if prefix else session.workspace_folder
            files = self.storage_resolver.list_workspace(
                pillar=session.active_pillar,
                workspace_folder=folder,
                include_common=False,
            )
            pcap_files = [
                f for f in files
                if any(f["filename"].lower().endswith(ext) for ext in PCAP_EXTENSIONS)
            ]
        except Exception as e:
            print(f"  Bucket listing failed: {e}")
            return None

        if not pcap_files:
            print(f"  No PCAP files found in bucket folder.")
            return None

        parser_name = "dpkt (fast mode)" if use_dpkt else "scapy"
        print(f"  Found {len(pcap_files)} PCAP file(s) in bucket")
        print(f"  Parser: {parser_name}")
        print()

        cumulative = get_pcap_session()
        loaded = 0

        for i, f_info in enumerate(pcap_files, 1):
            fname = f_info["filename"]
            print(f"  [{i}/{len(pcap_files)}] Downloading & parsing {fname}...")
            try:
                from framework.cloud.resolver import ResolvedPath
                resolved = ResolvedPath(
                    bucket=f_info["bucket"],
                    object_path=f_info["object_path"],
                    source=f_info["source"],
                    workspace_folder=folder,
                )

                local_dest = (
                    self.workspace_path / "artifacts"
                    / session.session_id / fname
                )
                local_dest.parent.mkdir(parents=True, exist_ok=True)
                self.storage_resolver.download(resolved, local_dest)

                new_session = parse_fn(str(local_dest))
                if cumulative is None:
                    cumulative = new_session
                else:
                    cumulative.merge_into(new_session)
                loaded += 1
                print(f"    ✓ {new_session.packet_count:,} packets")
            except Exception as e:
                print(f"    ✗ Failed: {e}")

        if cumulative and loaded > 0:
            set_pcap_session(cumulative)
            print()
            print(f"  Merge complete — {loaded} file(s) loaded")
            self._print_merge_summary(cumulative)
        else:
            print("  No files were successfully parsed.")
        return True

    def _print_merge_summary(self, session) -> None:
        """Print a summary of the cumulative merged session."""
        from plugins.network_forensics.pcap_metadata_summary.tool import (
            _format_duration,
            is_internal,
        )
        internal = sum(1 for ip in session.unique_ips if is_internal(ip))
        external = len(session.unique_ips) - internal
        print(
            f"  Cumulative: {session.packet_count:,} packets, "
            f"{len(session.unique_ips)} IPs ({internal} internal, {external} external), "
            f"duration {_format_duration(session.duration_seconds)}"
        )
        if session.ot_transactions:
            from collections import Counter as _Counter
            ot_protos = _Counter(t["protocol"] for t in session.ot_transactions)
            ot_summary = ", ".join(f"{p}:{c}" for p, c in ot_protos.most_common(5))
            print(f"  ✓ OT/ICS protocols: {ot_summary}")
        if session.cleartext_creds:
            print(f"  ⚠️  Cleartext credentials detected: {len(session.cleartext_creds)}")
        print(f"  PCAP ready — use 'run pcap_metadata_summary {{\"mode\": \"summary\"}}' or any pcap tool.")

    # -------------------------------------------------------------------
    # Zeek Commands — Large PCAP Processing via Cloud Build
    # -------------------------------------------------------------------

    # Persistent state for tracking Zeek jobs across commands
    _zeek_jobs: dict[str, dict] = {}
    _zeek_listed_folders: list[str] = []

    _ZEEK_SUBCOMMANDS = ("status", "load", "jobs", "list")

    def complete_zeek(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        """Complete 'zeek': a subcommand or filename first, then --async or a known id.

        No completer existed for this command either — same gap 'load' had
        before complete_load. Job/output identifiers only ever come from
        this session's own _zeek_jobs state, never from GCS, so completion
        can never block on the network.
        """
        parts = line[:begidx].split()
        args_before = parts[1:] if parts and parts[0] == "zeek" else parts

        if not args_before:
            candidates = set(self._ZEEK_SUBCOMMANDS) | set(self._complete_path(text))
            return [c for c in sorted(candidates) if c.startswith(text)]

        first = args_before[0]
        if first == "status":
            return [b for b in self._zeek_jobs if b.startswith(text)]
        if first == "load":
            rest = args_before[1:]
            if not rest:
                candidates = {"--merge"}
            elif rest[0] == "--merge":
                return []
            else:
                candidates = set()
            folders = {
                job["output_prefix"].rsplit("/", 1)[-1]
                for job in self._zeek_jobs.values()
                if job.get("output_prefix")
            }
            candidates |= folders
            return [f for f in sorted(candidates) if f.startswith(text)]
        if first in ("jobs", "list"):
            return []
        # First token was a filename/gs:// URI — only --async is left to offer.
        if "--async" in args_before:
            return []
        return [c for c in ("--async",) if c.startswith(text)]

    def do_zeek(self, arg: str) -> None:
        """Process a large PCAP with Zeek via Cloud Build.

        Submits the PCAP to a Cloud Build job running Zeek, then loads
        the resulting logs so all downstream tools work identically to
        a local PCAP load.

        File resolution uses the same order as 'load':
          1. Explicit gs:// URI
          2. Network forensics pillar bucket (workspace, then root)
          3. Common bucket

        Zeek output is stored in the network forensics bucket under
        zeek-output/<pcap_name>-<timestamp>/.

        Usage:
          zeek <filename_or_gs_uri>                Submit Zeek job and wait
          zeek <filename_or_gs_uri> --async        Submit and return immediately
          zeek status [build_id]                   Check job status
          zeek load [folder_name]                  Load Zeek logs (from bucket or gs://)
          zeek load [#]                            Load by index from 'zeek list'
          zeek load --merge #,#,#                  Merge multiple outputs by index
          zeek load --merge # # #                  Merge multiple (space-separated)
          zeek jobs                                List submitted jobs
          zeek list                                List available Zeek outputs (numbered)

        Examples:
          zeek massive.pcap                        Resolve from network forensics bucket
          zeek gs://my-bucket/captures/big.pcap    Explicit URI
          zeek massive.pcap --async
          zeek status
          zeek load massive-20260514-abc12345      Load from zeek-output/ in bucket
          zeek load                                Load most recent Zeek output
          zeek load 5                              Load output #5 from zeek list
          zeek load --merge 19,27,35,11            Merge outputs by index
          zeek load --merge 19 27 35 11            Same, space-separated
          zeek list                                Show available Zeek output folders
        """
        if not arg.strip():
            print("  Usage: zeek <filename_or_gs_uri> [--async]")
            print("         zeek status [build_id]")
            print("         zeek load [folder_name | #]")
            print("         zeek load --merge #,#,# or --merge # # #")
            print("         zeek list")
            print("         zeek jobs")
            return

        parts = shlex.split(arg.strip())
        subcommand = parts[0]

        if subcommand == "status":
            self._zeek_status(parts[1] if len(parts) > 1 else None)
        elif subcommand == "load":
            # --merge must come before indices: zeek load --merge 1,2,3
            rest = parts[1:]
            if rest and rest[0] == "--merge":
                raw_refs = rest[1:]
                refs: list[str] = []
                for r in raw_refs:
                    refs.extend(r.split(","))
                refs = [r.strip() for r in refs if r.strip()]
                if len(refs) < 2:
                    print("  Usage: zeek load --merge #,#,# or --merge # # #")
                    print("  Run 'zeek list' first to see numbered outputs.")
                    return
                self._zeek_load_merge(refs)
            else:
                folder_ref = rest[0] if rest else None
                folder_ref = self._zeek_resolve_index(folder_ref)
                self._zeek_load(folder_ref)
        elif subcommand == "list":
            self._zeek_list_outputs()
        elif subcommand == "jobs":
            self._zeek_list_jobs()
        else:
            # It's a PCAP reference — resolve it
            async_mode = "--async" in parts
            pcap_ref = subcommand
            pcap_uri = self._zeek_resolve_pcap(pcap_ref)
            if pcap_uri:
                self._zeek_submit(pcap_uri, async_mode=async_mode)

    def _zeek_get_nf_bucket(self) -> str | None:
        """Get the network forensics bucket name from the storage resolver."""
        if self.storage_resolver:
            return self.storage_resolver.config.bucket_for_pillar("network_forensics")
        return None

    def _zeek_resolve_pcap(self, pcap_ref: str) -> str | None:
        """Resolve a PCAP reference to a gs:// URI.

        Resolution order:
          1. #N from the last 'files' listing → that row's URI
          2. Already a gs:// URI → use as-is
          3. Filename → look in network forensics bucket (workspace, then root)
          4. Filename → look in common bucket
        """
        if _FILE_REF_RE.match(pcap_ref):
            entry = self._resolve_file_ref(pcap_ref)
            if entry is None:
                return None
            print(f"  {pcap_ref} → {entry.file.uri}")
            return entry.file.uri

        # 1. Explicit gs:// URI
        if pcap_ref.startswith("gs://"):
            return pcap_ref

        # 2. Resolve via storage resolver (same as 'load' command)
        session = self.session_manager.get_current_session()
        if not session:
            print("  No active session. Use 'new' to create one first.")
            return None

        pillar = "network_forensics"

        if self.storage_resolver:
            resolved = self.storage_resolver.resolve(
                filename=pcap_ref,
                pillar=pillar,
                workspace_folder=session.workspace_folder,
            )
            if resolved:
                print(f"  Found: {resolved.display}")
                return resolved.uri

        # Not found
        nf_bucket = self._zeek_get_nf_bucket()
        print(f"  File not found: {pcap_ref}")
        if nf_bucket:
            print(f"  Searched: gs://{nf_bucket}/")
            if session.workspace_folder:
                print(f"  Workspace: {session.workspace_folder}")
            print(f"\n  Upload first: gsutil cp {pcap_ref} gs://{nf_bucket}/")
        return None

    def _zeek_submit(self, pcap_uri: str, async_mode: bool = False) -> None:
        """Submit a Zeek Cloud Build job."""
        if not os.environ.get("K_SERVICE"):
            print("  ⚠  Zeek Cloud Build integration requires Cloud Run (GCP).")
            print("  For local use, install Zeek directly:")
            print("    zeek -r file.pcap LogAscii::use_json=T local")
            return

        print(f"  Submitting Zeek job for: {pcap_uri}")
        print(f"  Machine: E2_HIGHCPU_32 (32 vCPU, 32 GB RAM, 500 GB disk)")

        try:
            from ..cloud.gcp.zeek import ZeekCloudBuildClient

            client = ZeekCloudBuildClient()
            job = client.submit_zeek_job(pcap_uri=pcap_uri)

            build_id = job["build_id"]
            output_prefix = job["output_prefix"]

            # Track the job
            self._zeek_jobs[build_id] = job

            print(f"  ✓ Build submitted: {build_id}")
            print(f"  Output will be at: {output_prefix}/")

            log_user_activity("zeek_submit", {
                "build_id": build_id,
                "pcap_uri": pcap_uri,
                "output_prefix": output_prefix,
            })

            if async_mode:
                print()
                print(f"  Running in background. Check with:")
                print(f"    zeek status {build_id}")
                print(f"  When complete, load with:")
                print(f"    zeek load {output_prefix}")
                return

            # Synchronous — wait for completion
            print(f"  ⏳ Waiting for Zeek to finish (polling every 30s)...")
            print(f"  This may take 30-60 minutes for large PCAPs.")
            print(f"  Press Ctrl+C to stop waiting (job continues in background).")
            print()

            try:
                def _progress(status):
                    s = status.get("status", "?")
                    d = status.get("duration", "")
                    if d:
                        print(f"\r  Status: {s} ({d})   ", end="", flush=True)
                    else:
                        print(f"\r  Status: {s}   ", end="", flush=True)

                final = client.wait_for_completion(
                    build_id,
                    poll_interval=30,
                    progress_callback=_progress,
                )
                print()  # newline after \r progress

                self._zeek_jobs[build_id] = {**job, **final}

                if final.get("status") == "SUCCESS":
                    duration = final.get("duration", "unknown")
                    print(f"  ✓ Zeek complete in {duration}.")
                    print(f"  Loading Zeek logs from {output_prefix}/...")
                    self._zeek_load(output_prefix)
                else:
                    status = final.get("status", "UNKNOWN")
                    print(f"  ✗ Zeek job finished with status: {status}")
                    if final.get("log_url"):
                        print(f"  Logs: {final['log_url']}")
            except KeyboardInterrupt:
                print()
                print(f"  Stopped waiting. Job continues in background.")
                print(f"  Check:  zeek status {build_id}")
                print(f"  Load:   zeek load {output_prefix}")

        except ImportError:
            print("  ✗ google-cloud-build not installed.")
            print("  Install with: pip install google-cloud-build")
        except Exception as e:
            print(f"  ✗ Failed to submit Zeek job: {e}")
            logger.exception("Zeek submit failed")

    def _zeek_status(self, build_id: str | None = None) -> None:
        """Check Zeek job status."""
        if not build_id:
            if not self._zeek_jobs:
                print("  No Zeek jobs submitted this session.")
                return
            # Show latest job
            build_id = list(self._zeek_jobs.keys())[-1]

        try:
            from ..cloud.gcp.zeek import ZeekCloudBuildClient

            client = ZeekCloudBuildClient()
            status = client.get_build_status(build_id)

            print(f"  Build ID: {build_id}")
            print(f"  Status:   {status.get('status', 'UNKNOWN')}")
            if status.get("duration"):
                print(f"  Duration: {status['duration']}")
            if status.get("log_url"):
                print(f"  Logs:     {status['log_url']}")

            # Update tracked job
            if build_id in self._zeek_jobs:
                self._zeek_jobs[build_id].update(status)

            if status.get("status") == "SUCCESS":
                output = self._zeek_jobs.get(build_id, {}).get("output_prefix")
                if output:
                    print(f"\n  Ready to load: zeek load {output}")

        except ImportError:
            print("  ✗ google-cloud-build not installed.")
        except Exception as e:
            print(f"  ✗ Failed to check status: {e}")

    def _zeek_load(self, folder_ref: str | None = None, merge: bool = False) -> None:
        """Download and load Zeek logs from GCS into the session.

        Resolution:
          - No argument: load most recent Zeek output from the NF bucket
          - Bare folder name: resolve from zeek-output/ in NF bucket
          - gs:// URI: use as-is

        When merge=True, the parsed session is merged into whatever
        PcapSession is already active instead of replacing it — used by
        'zeek load --merge #,#,#' to accumulate multiple outputs.
        """
        if not self.session_manager.get_current_session():
            print("  No active session. Use 'new' to create one first.")
            return

        try:
            from google.cloud import storage as gcs_storage
            from plugins.network_forensics.pcap_metadata_summary.zeek_loader import parse_zeek_logs
            from plugins.network_forensics.pcap_metadata_summary.tool import (
                get_pcap_session, set_pcap_session, is_internal, _format_duration,
            )
            import tempfile

            client = gcs_storage.Client()
            nf_bucket = self._zeek_get_nf_bucket()

            # Resolve the output prefix
            if folder_ref and folder_ref.startswith("gs://"):
                # Explicit gs:// URI
                output_prefix = folder_ref.rstrip("/")
                prefix_clean = output_prefix.replace("gs://", "")
                parts = prefix_clean.split("/", 1)
                bucket_name = parts[0]
                prefix_path = parts[1] + "/" if len(parts) > 1 else ""
            elif folder_ref:
                # Bare folder name → look in zeek-output/ in NF bucket
                if not nf_bucket:
                    print("  ✗ No network forensics bucket configured.")
                    return
                bucket_name = nf_bucket
                prefix_path = f"zeek-output/{folder_ref}/"
                output_prefix = f"gs://{bucket_name}/zeek-output/{folder_ref}"
            else:
                # No argument → find most recent zeek-output folder
                if not nf_bucket:
                    print("  ✗ No network forensics bucket configured.")
                    return
                bucket_name = nf_bucket

                # List zeek-output/ subfolders and pick the latest
                bucket_obj = client.bucket(bucket_name)
                blobs = list(bucket_obj.list_blobs(prefix="zeek-output/", delimiter="/"))

                # Get subfolder prefixes
                prefixes = []
                # list_blobs with delimiter populates bucket_obj.list_blobs().prefixes
                iterator = bucket_obj.list_blobs(prefix="zeek-output/", delimiter="/")
                # Consume the iterator to populate prefixes
                _ = list(iterator)
                for p in iterator.prefixes:
                    prefixes.append(p.rstrip("/"))

                if not prefixes:
                    print(f"  No Zeek outputs found in gs://{bucket_name}/zeek-output/")
                    print(f"  Submit a job first: zeek <filename.pcap>")
                    return

                # Most recent (sorted alphabetically — timestamps in folder name)
                latest = sorted(prefixes)[-1]
                prefix_path = latest + "/"
                output_prefix = f"gs://{bucket_name}/{latest}"
                folder_name = latest.rsplit("/", 1)[-1]
                print(f"  Auto-selected latest output: {folder_name}")

            # Check for the most recent job's output prefix
            if not folder_ref and self._zeek_jobs:
                latest_job = list(self._zeek_jobs.values())[-1]
                if latest_job.get("output_prefix"):
                    output_prefix = latest_job["output_prefix"].rstrip("/")
                    prefix_clean = output_prefix.replace("gs://", "")
                    parts = prefix_clean.split("/", 1)
                    bucket_name = parts[0]
                    prefix_path = parts[1] + "/" if len(parts) > 1 else ""

            # Download Zeek logs from GCS to local temp dir
            local_dir = Path(tempfile.mkdtemp(prefix="eventmill_zeek_"))

            bucket_obj = client.bucket(bucket_name)
            blobs = list(bucket_obj.list_blobs(prefix=prefix_path))

            log_files = [b for b in blobs if b.name.endswith(".log")]
            if not log_files:
                print(f"  No .log files found at {output_prefix}/")
                if nf_bucket:
                    print(f"  Try: zeek list")
                return

            print(f"  Downloading {len(log_files)} Zeek log files from {output_prefix}/...")
            for blob in log_files:
                filename = blob.name.rsplit("/", 1)[-1]
                local_path = local_dir / filename
                blob.download_to_filename(str(local_path))
                size_mb = blob.size / (1024 * 1024) if blob.size else 0
                print(f"    ✓ {filename} ({size_mb:.1f} MB)")

            # Parse Zeek logs into PcapSession
            print(f"  Parsing Zeek logs...")
            session = parse_zeek_logs(local_dir)

            if merge:
                existing = get_pcap_session()
                if existing is None:
                    set_pcap_session(session)
                else:
                    existing.merge_into(session)
                    session = existing
            else:
                set_pcap_session(session)

            # Print summary (same format as _auto_parse_pcap)
            internal = sum(1 for ip in session.unique_ips if is_internal(ip))
            external = len(session.unique_ips) - internal
            duration = session.duration_seconds

            print(
                f"  ✓ {len(session.conversations):,} connections, "
                f"{len(session.unique_ips)} IPs ({internal} internal, {external} external), "
                f"duration {_format_duration(duration)}"
            )
            if session.dns_queries:
                print(f"  ✓ {len(session.dns_queries):,} DNS queries")
            if session.tls_handshakes:
                print(f"  ✓ {len(session.tls_handshakes):,} TLS handshakes")
            if session.http_requests:
                print(f"  ✓ {len(session.http_requests):,} HTTP requests")
            if session.ot_transactions:
                from collections import Counter as _Counter
                ot_protos = _Counter(t["protocol"] for t in session.ot_transactions)
                ot_summary = ", ".join(f"{p}:{c}" for p, c in ot_protos.most_common(5))
                print(f"  ✓ OT/ICS protocols: {ot_summary}")
            if session.cleartext_creds:
                print(f"  ⚠️  Cleartext credentials detected: {len(session.cleartext_creds)}")

            # Register as artifact
            session_data = self.session_manager.get_current_session()
            if session_data:
                self.session_manager.register_artifact(
                    artifact_type="json_events",
                    file_path=str(local_dir),
                    metadata={
                        "source": "zeek",
                        "gcs_prefix": output_prefix,
                        "connections": len(session.conversations),
                        "unique_ips": len(session.unique_ips),
                    },
                )

            print()
            print(f"  PCAP session ready — use any pcap tool:")
            print(f"    run pcap_threat_hunter")
            print(f"    run pcap_ai_analyzer {{\"mode\": \"threat_hunt\"}}")
            print(f"    run pcap_ip_search {{\"query\": \"10.1.5.22\"}}")

            log_user_activity("zeek_load", {
                "source": output_prefix,
                "connections": len(session.conversations),
                "unique_ips": len(session.unique_ips),
            })

        except ImportError as e:
            print(f"  ✗ Missing dependency: {e}")
        except Exception as e:
            print(f"  ✗ Failed to load Zeek logs: {e}")
            logger.exception("Zeek load failed")

    def _zeek_list_jobs(self) -> None:
        """List all Zeek jobs submitted this session."""
        if not self._zeek_jobs:
            print("  No Zeek jobs submitted this session.")
            return

        print(f"  {'Build ID':40s} {'Status':12s} {'PCAP':40s}")
        print(f"  {'─' * 40} {'─' * 12} {'─' * 40}")
        for build_id, job in self._zeek_jobs.items():
            status = job.get("status", "UNKNOWN")
            pcap = job.get("pcap_uri", "?")
            # Truncate PCAP URI for display
            if len(pcap) > 40:
                pcap = "..." + pcap[-37:]
            print(f"  {build_id:40s} {status:12s} {pcap:40s}")

    def _zeek_resolve_index(self, ref: str | None) -> str | None:
        """Resolve a numeric index from the last 'zeek list' to a folder name."""
        if ref is None:
            return None
        if ref.isdigit():
            if not self._zeek_listed_folders:
                print(f"  ✗ No folder list cached. Run 'zeek list' first.")
                return None
            idx = int(ref) - 1
            if 0 <= idx < len(self._zeek_listed_folders):
                return self._zeek_listed_folders[idx]
            print(f"  ✗ Index {ref} out of range (valid: 1-{len(self._zeek_listed_folders)}). Run 'zeek list' to refresh.")
            return None
        return ref

    def _zeek_load_merge(self, refs: list[str]) -> None:
        """Load and merge multiple Zeek outputs by folder name or index."""
        folders = []
        for ref in refs:
            resolved = self._zeek_resolve_index(ref)
            if resolved is None:
                return
            folders.append(resolved)

        print(f"  Merging {len(folders)} Zeek outputs...")
        for i, folder in enumerate(folders):
            print(f"    [{i + 1}/{len(folders)}] {folder}")
            # First load creates the session, subsequent ones merge into it.
            self._zeek_load(folder, merge=(i > 0))

    def _zeek_list_outputs(self) -> None:
        """List available Zeek output folders in the network forensics bucket."""
        nf_bucket = self._zeek_get_nf_bucket()
        if not nf_bucket:
            print("  ✗ No network forensics bucket configured.")
            return

        try:
            from google.cloud import storage as gcs_storage

            client = gcs_storage.Client()
            bucket = client.bucket(nf_bucket)

            # List subfolders under zeek-output/
            iterator = bucket.list_blobs(prefix="zeek-output/", delimiter="/")
            # Consume iterator to populate prefixes
            _ = list(iterator)
            prefixes = sorted(iterator.prefixes)

            if not prefixes:
                print(f"  No Zeek outputs in gs://{nf_bucket}/zeek-output/")
                print(f"  Submit a job: zeek <filename.pcap>")
                return

            print(f"  Zeek outputs in gs://{nf_bucket}/zeek-output/:")
            print(f"  {'#':4s} {'Folder':50s} Load command")
            print(f"  {'─' * 4} {'─' * 50} {'─' * 40}")
            folders = [p.replace("zeek-output/", "").rstrip("/") for p in prefixes if p.replace("zeek-output/", "").rstrip("/")]
            self._zeek_listed_folders = folders
            for i, folder in enumerate(folders, 1):
                print(f"  {i:<4d} {folder:50s} zeek load {folder}")

        except ImportError:
            print("  ✗ google-cloud-storage not installed.")
        except Exception as e:
            print(f"  ✗ Failed to list Zeek outputs: {e}")

    def do_artifacts(self, arg: str) -> None:
        """List loaded artifacts in the current session.
        
        Usage: artifacts
        """
        if not self.session_manager.get_current_session():
            print("  No active session.")
            return
        
        artifacts = self.session_manager.list_artifacts()
        if not artifacts:
            print("  No artifacts loaded. Use 'load <file_path>' to add one.")
            return
        
        print(f"  {'ID':12s} {'Type':16s} {'Source':16s} File")
        print(f"  {'─' * 12} {'─' * 16} {'─' * 16} {'─' * 30}")
        
        for a in artifacts:
            source = a.source_tool or "user"
            filename = Path(a.file_path).name
            print(f"  {a.artifact_id:12s} {a.artifact_type:16s} {source:16s} {filename}")
    
    # -------------------------------------------------------------------
    # Tool Commands
    # -------------------------------------------------------------------
    
    def do_tools(self, arg: str) -> None:
        """List available tools, scoped to the active pillar.

        Usage: tools [pillar] [--all]

        With a pillar active, the listing is that pillar's tools - including
        tools from elsewhere that name it in their manifest's also_useful_in -
        plus any tool that consumes an artifact type you have loaded.
        '--all' shows every tool; naming a pillar shows that one.
        """
        stripped = arg.strip()
        pillar = ""
        show_all = False

        if stripped:
            try:
                tokens = shlex.split(stripped)
            except ValueError as e:
                print(f"  Could not parse arguments: {e}")
                return
            for token in tokens:
                if token == "--all":
                    show_all = True
                elif token.startswith("--"):
                    print(f"  Unknown flag {token}. Use --all, or name a pillar.")
                    return
                elif pillar:
                    print("  Usage: tools [pillar] [--all]")
                    return
                else:
                    pillar = token

        if pillar and show_all:
            print("  Name a pillar or pass --all, not both.")
            return

        known_pillars = self.plugin_loader.list_pillars()

        if pillar:
            if pillar not in known_pillars:
                print(f"  No tools for pillar {pillar!r}.")
                print(f"  Loaded pillars: {', '.join(sorted(known_pillars))}")
                return
            self._print_pillar_rows(pillar, self.plugin_loader.get_for_pillar(pillar))
            return

        all_plugins = self.plugin_loader.list_all()
        if not all_plugins:
            print("  No tools available.")
            return

        session = self.session_manager.get_current_session()
        active = session.active_pillar if session else None

        if show_all or not active or active not in known_pillars:
            self._print_tool_rows(all_plugins, show_pillar=True)
            if not show_all and not active:
                print()
                print("  Set a pillar with 'pillar <name>' to narrow this list.")
            return

        pillar_plugins = self.plugin_loader.get_for_pillar(active)
        related = self._related_tools(active, pillar_plugins)

        print(f"  {active} tools")
        self._print_pillar_rows(active, pillar_plugins)

        if related:
            print()
            print("  Related — these consume artifacts you have loaded")
            self._print_tool_rows(related, show_pillar=True)

        shown = {p.tool_name for p in pillar_plugins} | {p.tool_name for p in related}
        hidden = [p for p in all_plugins if p.tool_name not in shown]
        if hidden:
            others = sorted({p.pillar for p in hidden})
            print()
            print(f"  {len(hidden)} more in other pillars: 'tools --all', or 'tools <pillar>'")
            print(f"  ({', '.join(others)})")

    def _related_tools(
        self,
        active_pillar: str,
        pillar_plugins: list[LoadedPlugin],
    ) -> list[LoadedPlugin]:
        """Tools outside the active pillar that consume a loaded artifact type.

        This is the session-driven half of cross-pillar relevance: a PCAP tool
        earns a place in a threat_modeling listing once a PCAP is loaded. The
        declared half is the manifest's also_useful_in, applied by the caller.
        """
        try:
            loaded_types = {a.artifact_type for a in self.session_manager.list_artifacts()}
        except ValueError:
            return []
        if not loaded_types:
            return []

        in_pillar = {p.tool_name for p in pillar_plugins}
        related = [
            p
            for p in self.plugin_loader.list_all()
            if p.tool_name not in in_pillar
            and loaded_types.intersection(p.manifest.artifacts_consumed or [])
        ]
        return sorted(related, key=lambda p: (p.pillar, p.tool_name))

    def _print_pillar_rows(self, pillar: str, plugins: list[LoadedPlugin]) -> None:
        """Print one pillar's tools, including any that only declare it.

        The pillar column appears only when a borrowed tool makes it vary, and
        a footnote says why a row from another pillar is in the listing.
        """
        borrowed = [p for p in plugins if p.pillar != pillar]
        self._print_tool_rows(plugins, show_pillar=bool(borrowed))
        if borrowed:
            print(f"  Rows outside {pillar} declare it in the manifest's also_useful_in.")

    def _print_tool_rows(self, plugins: list[LoadedPlugin], show_pillar: bool) -> None:
        """Print a tool table, with the pillar column only when it varies."""
        if not plugins:
            print("  No tools available.")
            return

        if show_pillar:
            print(f"  {'Display Name':30s} {'Invoke As':30s} {'Pillar':20s} {'Stability':12s} Description")
            print(f"  {'─' * 30} {'─' * 30} {'─' * 20} {'─' * 12} {'─' * 50}")
        else:
            print(f"  {'Display Name':30s} {'Invoke As':30s} {'Stability':12s} Description")
            print(f"  {'─' * 30} {'─' * 30} {'─' * 12} {'─' * 50}")

        for plugin in plugins:
            m = plugin.manifest
            desc = m.description_short[:80] if m.description_short else "—"
            invoke = f"run {m.tool_name}"
            if show_pillar:
                print(f"  {m.display_name:30s} {invoke:30s} {m.pillar:20s} {m.stability:12s} {desc}")
            else:
                print(f"  {m.display_name:30s} {invoke:30s} {m.stability:12s} {desc}")
    
    def do_help(self, arg: str) -> None:
        """Show help for a command or tool.

        Usage: help [command_or_tool_name]

        For tool-specific usage, pass the tool name:
          help threat_report_analyzer
        """
        if arg:
            plugin = self.plugin_loader.get(arg.strip())
            if plugin:
                self._print_tool_help(plugin)
                return
        super().do_help(arg)

    def _print_tool_help(self, plugin: LoadedPlugin) -> None:
        """Print help for a tool by rendering its README.md."""
        m = plugin.manifest
        readme_path = m.plugin_dir / "README.md"

        print()
        print(f"  {'─' * 60}")
        print(f"  {m.display_name}  ({m.tool_name})")
        print(f"  Pillar: {m.pillar}   Stability: {m.stability}")
        print(f"  Invoke: run {m.tool_name} --key value [--key value ...]")
        print(f"      or: run {m.tool_name} {{\"key\": \"value\"}}   (for list/object arguments)")
        print(f"  {'─' * 60}")
        print()

        self._print_tool_arguments(plugin)

        if readme_path.exists():
            rendered = self._render_markdown_plain(readme_path.read_text(encoding="utf-8"))
            print(rendered)
        else:
            print(f"  {m.description_short}")
            print()
            print("  No README.md available for this tool.")
        print()

    def _print_tool_arguments(self, plugin: LoadedPlugin) -> None:
        """Print the tool's arguments as flags, derived from its input schema."""
        import textwrap

        schema = self._plugin_input_schema(plugin)
        if not schema:
            return
        required_list, one_of = self._plugin_required_inputs(plugin)
        required = set(required_list)

        print("  Arguments")
        print(f"  {'─' * 9}")

        for name, spec in schema.items():
            declared = self._declared_type(spec) or "string"
            item_type = self._declared_type(spec.get("items") or {})

            if declared == "boolean":
                flag = f"--{name}"
            elif declared == "array" and item_type in (None, "string"):
                flag = f"--{name} a,b,c"
            elif declared in ("object",) or (declared == "array" and item_type not in (None, "string")):
                flag = f'{{"{name}": ...}}'
            else:
                flag = f"--{name} <{declared}>"

            notes = []
            if name in required:
                notes.append("required")
            if "default" in spec:
                notes.append(f"default {spec['default']}")
            if spec.get("enum"):
                notes.append("one of: " + ", ".join(str(v) for v in spec["enum"]))
            if "minimum" in spec and "maximum" in spec:
                notes.append(f"range {spec['minimum']}-{spec['maximum']}")
            elif "minimum" in spec:
                notes.append(f"min {spec['minimum']}")
            elif "maximum" in spec:
                notes.append(f"max {spec['maximum']}")
            if declared == "object" or (declared == "array" and item_type not in (None, "string")):
                notes.append("JSON form only")

            print(f"    {flag:<34} {'; '.join(notes)}".rstrip())
            desc = spec.get("description")
            if desc:
                print(
                    textwrap.fill(
                        desc, width=78, initial_indent="        ", subsequent_indent="        "
                    )
                )
        if one_of:
            print()
            print("    Supply one of: " + ", ".join(f"--{n}" for n in one_of))
        print()

    @staticmethod
    def _render_markdown_plain(text: str) -> str:
        """Convert Markdown to readable plain-text for terminal display."""
        import re
        import textwrap

        lines = text.splitlines()
        out: list[str] = []
        para: list[str] = []
        in_code = False

        def flush_paragraph() -> None:
            """Wrap the buffered paragraph as one block, not line by line."""
            if para:
                out.append(
                    textwrap.fill(
                        " ".join(para),
                        width=78,
                        initial_indent="  ",
                        subsequent_indent="  ",
                    )
                )
                para.clear()

        for line in lines:
            # Toggle fenced code block
            if line.startswith("```"):
                flush_paragraph()
                in_code = not in_code
                out.append("")
                continue

            if in_code:
                out.append(f"    {line}")
                continue

            # H1
            if line.startswith("# "):
                flush_paragraph()
                title = line[2:].strip()
                out.append(f"\n  {title}")
                out.append(f"  {'═' * len(title)}")
                continue
            # H2
            if line.startswith("## "):
                flush_paragraph()
                title = line[3:].strip()
                out.append(f"\n  {title}")
                out.append(f"  {'─' * len(title)}")
                continue
            # H3
            if line.startswith("### "):
                flush_paragraph()
                title = line[4:].strip()
                out.append(f"\n  {title}:")
                continue

            # Strip inline bold/italic/code markers
            line = re.sub(r"\*\*(.+?)\*\*", r"\1", line)
            line = re.sub(r"\*(.+?)\*", r"\1", line)
            line = re.sub(r"`(.+?)`", r"\1", line)

            # Table separator rows — skip
            if re.match(r"^\|[-| :]+\|$", line.strip()):
                continue

            # Table rows and list items — indent and pass through
            if line.startswith("|") or line.startswith("- ") or line.startswith("* ") or re.match(r"^\d+\. ", line):
                flush_paragraph()
                out.append(f"  {line}")
                continue

            # Blank lines
            if not line.strip():
                flush_paragraph()
                out.append("")
                continue

            # Paragraph text — buffered so the whole paragraph wraps at 78
            para.append(line.strip())

        flush_paragraph()
        return "\n".join(out)

    def _plugin_input_schema(self, plugin: LoadedPlugin) -> dict[str, Any]:
        """Return the ``properties`` block of a plugin's input schema, cached."""
        name = plugin.tool_name
        if name not in self._input_schema_cache:
            props: dict[str, Any] = {}
            schema_path = plugin.manifest.plugin_dir / "schemas" / "input.schema.json"
            if schema_path.exists():
                try:
                    raw = json.loads(schema_path.read_text(encoding="utf-8"))
                    props = raw.get("properties") or {}
                except (OSError, json.JSONDecodeError) as e:
                    logger.warning("Could not read input schema for %s: %s", name, e)
            self._input_schema_cache[name] = props
        return self._input_schema_cache[name]

    def _plugin_required_inputs(self, plugin: LoadedPlugin) -> tuple[list[str], list[str]]:
        """Return a plugin's required inputs as (always_required, one_of).

        ``one_of`` collects the single-key ``anyOf`` alternatives some schemas use
        to say "supply this argument or that one".
        """
        schema_path = plugin.manifest.plugin_dir / "schemas" / "input.schema.json"
        if not schema_path.exists():
            return [], []
        try:
            raw = json.loads(schema_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return [], []
        one_of: list[str] = []
        for branch in raw.get("anyOf") or []:
            for name in branch.get("required") or []:
                if name not in one_of:
                    one_of.append(name)
        return list(raw.get("required") or []), one_of

    @staticmethod
    def _declared_type(spec: dict[str, Any]) -> str | None:
        """Resolve a schema property's type, tolerating ``["string", "null"]`` unions."""
        declared = spec.get("type")
        if isinstance(declared, list):
            declared = next((t for t in declared if t != "null"), None)
        return declared

    def _coerce_flag_value(
        self, key: str, value: Any, spec: dict[str, Any]
    ) -> tuple[Any, str | None]:
        """Convert a --flag string to the type the plugin's input schema declares.

        Returns (value, None) on success or (None, message) on failure. Keys the
        schema does not declare are passed through unchanged for the plugin's own
        validate_inputs() to judge.
        """
        if value is True:  # bare --flag
            return True, None

        declared = self._declared_type(spec)

        if declared in (None, "string"):
            return value, None

        if declared == "boolean":
            low = value.strip().lower()
            if low in ("true", "yes", "on", "1"):
                return True, None
            if low in ("false", "no", "off", "0"):
                return False, None
            return None, f"--{key} expects true or false, got {value!r}."

        if declared == "integer":
            try:
                return int(value, 10) if isinstance(value, str) else int(value), None
            except ValueError:
                return None, f"--{key} expects a whole number, got {value!r}."

        if declared == "number":
            try:
                return float(value), None
            except ValueError:
                return None, f"--{key} expects a number, got {value!r}."

        if declared == "array":
            item_type = self._declared_type(spec.get("items") or {})
            if item_type in (None, "string"):
                return [v.strip() for v in value.split(",") if v.strip()], None
            return None, (
                f"--{key} takes structured values. Use the JSON form instead: "
                f'run <tool_name> {{"{key}": [...]}}'
            )

        if declared == "object":
            return None, (
                f"--{key} takes a structured value. Use the JSON form instead: "
                f'run <tool_name> {{"{key}": {{...}}}}'
            )

        return value, None

    def _local_path_for_entry(self, entry: FileListingEntry) -> Path | None:
        """Find the local copy of a listed file, if it has been loaded.

        Uses the id recorded when the row itself was loaded, and otherwise
        falls back to matching a session artifact by filename so a plain
        'load auth.log' still satisfies a later '#N'.
        """
        if entry.local_path and entry.local_path.exists():
            return entry.local_path

        for artifact in self.session_manager.list_artifacts():
            candidate = Path(artifact.file_path)
            if candidate.name == entry.file.filename and candidate.exists():
                entry.artifact_id = artifact.artifact_id
                entry.local_path = candidate
                return candidate

        return None

    def _expand_file_refs(
        self,
        pairs: list[tuple[str, Any]],
    ) -> tuple[list[tuple[str, Any]], bool]:
        """Replace '#N' flag values with the local path of that listed file.

        Only a value that is exactly '#N' is treated as a reference, so a
        literal like --query "#3" is untouched. '##N' escapes to a literal
        '#N'. Returns (pairs, ok); ok is False after printing an error.
        """
        expanded: list[tuple[str, Any]] = []
        for key, value in pairs:
            if not isinstance(value, str):
                expanded.append((key, value))
                continue

            if value.startswith("##"):
                expanded.append((key, value[1:]))
                continue

            if not _FILE_REF_RE.match(value):
                expanded.append((key, value))
                continue

            entry = self._resolve_file_ref(value)
            if entry is None:
                return [], False

            local = self._local_path_for_entry(entry)
            if local is None:
                print(
                    f"  {value} is a stored file "
                    f"({entry.file.object_path}), not a local one."
                )
                print(f"  Load it first:  load {value}")
                return [], False

            print(f"  {value} → {local}")
            expanded.append((key, str(local)))

        return expanded, True

    def _parse_flag_payload(self, raw: str, plugin: LoadedPlugin) -> dict[str, Any] | None:
        """Parse --key value flags into a typed payload.

        Values are typed from the plugin's input schema, so --line_limit 100
        arrives as an int while --query 404 stays a string. Returns None after
        printing a message when the flags cannot be parsed.
        """
        try:
            tokens = shlex.split(raw)
        except ValueError as e:
            print(f"  Could not parse arguments: {e}")
            return None

        pairs, error = _split_flags(tokens)
        if error:
            print(f"  {error}")
            return None

        expanded, ok = self._expand_file_refs(pairs)
        if not ok:
            return None
        pairs = expanded

        schema = self._plugin_input_schema(plugin)
        payload: dict[str, Any] = {}
        # An unrecognised flag aborts the run rather than being warned about
        # and passed through anyway. `--ignore_cap` for `--ignore_caps` used
        # to be accepted in silence and the run did the opposite of what the
        # operator asked, with nothing in the output saying so; a later fix
        # named the mistake but still ran the tool with it, which is not
        # actually safer — the operator's real request never ran either way,
        # just now with more text before it didn't. Naming the right path is
        # the job, inferring intent is not, and neither is running anyway.
        if schema:
            unknown = [k for k, _ in pairs if k not in schema]
            if unknown:
                known = ", ".join(f"--{k}" for k in sorted(schema))
                for key in dict.fromkeys(unknown):
                    print(
                        f"  --{key} is not an argument of {plugin.tool_name}."
                    )
                print(f"  Arguments {plugin.tool_name} accepts: {known}")
                return None
        for key, value in pairs:
            coerced, error = self._coerce_flag_value(key, value, schema.get(key) or {})
            if error:
                print(f"  {error}")
                return None
            # Repeating a list-valued flag appends rather than overwrites
            if isinstance(coerced, list) and isinstance(payload.get(key), list):
                payload[key].extend(coerced)
            else:
                payload[key] = coerced
        return payload

    def complete_run(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        # Complete tool names (first argument only)
        parts = line.split()
        if len(parts) <= 1 or (len(parts) == 2 and not line.endswith(" ")):
            all_tools = [p.tool_name for p in self.plugin_loader.list_all()]
            return [t for t in sorted(all_tools) if t.startswith(text)]

        # Past the tool name: complete this tool's own flags and, for
        # schema properties with an 'enum', their values — driven entirely
        # by the tool's input_schema, so a new tool gets this for free.
        plugin = self.plugin_loader.get(parts[1])
        if plugin is None:
            return []
        schema = self._plugin_input_schema(plugin)
        if not schema:
            return []

        # The token immediately before the word being completed tells a
        # flag name apart from a flag's value — 'run t --mode ' completing
        # '' has prev '--mode'; 'run t --mo' completing '--mo' has prev
        # the tool name, so it falls through to flag-name completion.
        before = line[:begidx].split()
        prev = before[-1] if before else ""
        prev_key = prev[2:] if prev.startswith("--") else None

        if prev_key and prev_key in schema:
            enum = schema[prev_key].get("enum")
            if not enum:
                return []  # no declared values to complete for this flag
            return [str(v) for v in enum if str(v).startswith(text)]

        # Completing a flag name. List-valued flags may legitimately repeat
        # (do_run appends rather than overwrites), everything else is
        # dropped from the list once it is already on the line.
        used = {tok[2:] for tok in parts[2:] if tok.startswith("--")}
        candidates = [
            f"--{name}" for name, spec in schema.items()
            if name not in used or self._declared_type(spec) == "array"
        ]
        return [c for c in sorted(candidates) if c.startswith(text)]

    def do_run(self, arg: str) -> None:
        """Run a tool on the current session.

        Usage: run <tool_name> --key value [--key value ...]

        Flags are the normal way to call a tool. Values are typed from the
        tool's input schema, so numbers and true/false arrive correctly:

          run log_navigator --action read --path access.log --line_limit 100
          run log_pattern_analyzer --mode discover --file_path mystery.log --ai_analysis
          run threat_report_analyzer --action search_reports --query "ransomware"

        Flag forms:
          --key value      set a value
          --key=value      same, needed when the value starts with '-'
          --key            a boolean flag, sets it true
          --key a,b,c      a list of text values
          --key #3         file #3 from the last 'files' listing, which
                           must already be loaded; --key ##3 is a literal

        JSON is the alternative for arguments a flag cannot express — lists of
        objects, or nested structures:

          run attack_path_visualizer {"format": "ascii", "stages": [{"name": "..."}]}

        Use 'help <tool_name>' for a tool's arguments.
        """
        if not self.session_manager.get_current_session():
            print("  No active session. Use 'new' to create one.")
            return
        
        parts = arg.strip().split(maxsplit=1)
        if not parts:
            print("  Usage: run <tool_name> [--key value ...] | [json_payload]")
            return
        
        tool_name = parts[0]
        plugin = self.plugin_loader.get(tool_name)
        
        if not plugin:
            print(f"  Tool not found: {tool_name}")
            return
        
        # Parse payload — supports JSON object or --flag style arguments
        payload: dict[str, Any] = {}
        if len(parts) > 1:
            raw = parts[1].strip()
            if raw.startswith("{"):
                try:
                    payload = json.loads(raw)
                except json.JSONDecodeError as e:
                    print(f"  Invalid JSON payload: {e}")
                    return
            else:
                parsed = self._parse_flag_payload(raw, plugin)
                if parsed is None:
                    return
                payload = parsed
        
        # Resolve artifact_id → file_path for plugins that need a file
        if "artifact_id" in payload:
            art_path = self.session_manager.get_artifact_path(payload["artifact_id"])
            if art_path is None:
                print(f"  Artifact not found: {payload['artifact_id']}")
                return
            # Inject file_path (most plugins) and path (log_navigator)
            # Keep artifact_id — plugins using registry lookup still need it
            payload.setdefault("file_path", str(art_path))
            payload.setdefault("path", str(art_path))
        
        # Get plugin instance
        instance = plugin.get_instance()
        
        # Validate inputs
        validation = instance.validate_inputs(payload)
        if not validation.ok:
            print(f"  Input validation failed:")
            for error in (validation.errors or []):
                print(f"    - {error}")
            return
        
        # Snapshot registered artifacts before execution to detect new ones afterwards
        _artifacts_before = {a.artifact_id for a in self.session_manager.list_artifacts()}

        # Build execution context
        session = self.session_manager.get_current_session()
        # Session artifacts carry the user-visible IDs shown by 'artifacts' command
        artifact_refs = [
            ArtifactRef(
                artifact_id=sa.artifact_id,
                artifact_type=sa.artifact_type,
                file_path=sa.file_path,
                source_tool=getattr(sa, "source_tool", None),
                metadata=getattr(sa, "metadata", None) or {},
            )
            for sa in self.session_manager.list_artifacts()
        ]
        # Append tool-produced artifacts from registry that aren't already present
        if self.artifact_registry:
            existing_ids = {a.artifact_id for a in artifact_refs}
            for ra in self.artifact_registry.list_all():
                if ra.artifact_id not in existing_ids:
                    artifact_refs.append(ra)
        
        def _register_artifact(
            artifact_type: str,
            file_path: str,
            source_tool: str,
            metadata: dict,
        ) -> ArtifactRef:
            """Persist tool-produced artifacts in session_manager (visible in 'artifacts') and return a canonical ArtifactRef."""
            session_art = self.session_manager.register_artifact(
                artifact_type=artifact_type,
                file_path=str(file_path),
                source_tool=source_tool,
                metadata=metadata or {},
            )
            return ArtifactRef(
                artifact_id=session_art.artifact_id,
                artifact_type=session_art.artifact_type,
                file_path=str(file_path),
                source_tool=source_tool,
                metadata=metadata or {},
            )

        # Apply the plugin's declared model_tier as the default for every LLM
        # call it makes. A plugin can still override per call with QueryHints.
        # model_tier "none" declares the plugin does no LLM work at all.
        model_tier = plugin.manifest.model_tier
        llm_connected = self.llm_client is not None and self.llm_client.connected
        selected_provider = self._provider_for(tool_name)
        if model_tier == "none" or not llm_connected:
            scoped_llm = None
        else:
            # The provider joins the tier here and nowhere else. Both are
            # per-execution decisions the operator owns, and the wrapper is
            # the one place a plugin cannot reach either of them.
            scoped_llm = TierScopedLLMClient(
                self.llm_client,
                default_tier=model_tier,
                default_provider=selected_provider,
            )

        context = ExecutionContext(
            session_id=session.session_id,
            selected_pillar=session.active_pillar or "",
            artifacts=artifact_refs,
            llm_enabled=scoped_llm is not None,
            llm_query=scoped_llm,
            model_tier=model_tier,
            register_artifact=_register_artifact,
            reference_data=ReferenceDataView(
                {
                    "mitre_techniques": get_mitre_db(),
                    "mitre_relationships": get_mitre_relationships(),
                }
            ),
        )
        
        # Track execution
        execution = self.session_manager.start_execution(
            tool_name=tool_name,
        )
        
        timeout = TimeoutClass.get_limit(plugin.manifest.timeout_class)
        note = self._provider_note(scoped_llm is not None, selected_provider)
        print(
            f"  Running {plugin.manifest.display_name}{note} "
            f"(timeout {timeout}s)..."
        )
        
        try:
            # Execute with thread-based timeout to prevent indefinite hangs
            _result_holder: list = [None]
            _error_holder: list = [None]

            def _run_plugin():
                try:
                    _result_holder[0] = instance.execute(payload, context)
                except Exception as exc:
                    _error_holder[0] = exc

            worker = threading.Thread(target=_run_plugin, daemon=True)
            worker.start()

            # Poll with a visible elapsed-time ticker instead of a single
            # silent join.  The periodic output also keeps the WebSocket
            # alive through Cloud Run's load-balancer.
            _tick = 10  # seconds between progress updates
            _elapsed = 0
            while _elapsed < timeout:
                worker.join(timeout=min(_tick, timeout - _elapsed))
                _elapsed += _tick
                if not worker.is_alive():
                    break
                print(f"  \u23f3 {_elapsed}s / {timeout}s ...", flush=True)

            if worker.is_alive():
                print(f"  \u2718 Timed out after {timeout}s")
                self.session_manager.complete_execution(
                    execution=execution,
                    status=ToolExecutionStatus.FAILED,
                    summary=f"Execution timed out after {timeout}s",
                )
                log_user_activity("run_tool", {
                    "tool_name": tool_name,
                    "execution_id": execution.execution_id,
                    "status": "timeout",
                })
                return

            if _error_holder[0] is not None:
                raise _error_holder[0]

            result = _result_holder[0]
            if result is None:
                raise RuntimeError("Plugin returned None instead of ToolResult")
            
            if result.ok:
                # Register output_artifacts declared by the plugin — unless the
                # plugin already registered that file via context.register_artifact
                # (threat_intel_ingester does both), which would list it twice.
                _already_registered = {
                    str(Path(a.file_path).resolve())
                    for a in self.session_manager.list_artifacts()
                    if a.artifact_id not in _artifacts_before
                }
                for oa in (result.output_artifacts or []):
                    oa_path = Path(oa.get("file_path", ""))
                    if str(oa_path.resolve()) in _already_registered:
                        continue
                    if oa_path.exists():
                        self.session_manager.register_artifact(
                            artifact_type=oa.get("artifact_type", "text"),
                            file_path=str(oa_path),
                            source_tool=tool_name,
                            metadata={"plugin_artifact_id": oa.get("artifact_id", "")},
                        )

                # Auto-persist output if the tool didn't register an artifact itself
                _artifacts_after = {a.artifact_id for a in self.session_manager.list_artifacts()}
                if not (_artifacts_after - _artifacts_before) and result.result is not None:
                    self._auto_persist_result(
                        result=result,
                        tool_name=tool_name,
                        artifacts_produced=getattr(plugin.manifest, "artifacts_produced", []) or [],
                    )

                summary = instance.summarize_for_llm(result)
                self.session_manager.complete_execution(
                    execution=execution,
                    status=ToolExecutionStatus.COMPLETED,
                    summary=summary,
                )
                
                # Log activity
                log_user_activity("run_tool", {
                    "tool_name": tool_name,
                    "execution_id": execution.execution_id,
                    "status": "completed",
                })
                
                print(f"  ✓ Completed successfully")
                print(f"\n  Summary:\n  {summary}")
                self._print_run_output(result, _artifacts_before)
                self._auto_export_run_output(tool_name, _artifacts_before)
            else:
                self.session_manager.complete_execution(
                    execution=execution,
                    status=ToolExecutionStatus.FAILED,
                    summary=result.message or "",
                )
                
                # Log activity
                log_user_activity("run_tool", {
                    "tool_name": tool_name,
                    "execution_id": execution.execution_id,
                    "status": "failed",
                    "error_code": str(result.error_code),
                })
                
                print(f"  ✗ Failed: {result.error_code}")
                if result.message:
                    print(f"    {result.message}")
                    
        except Exception as e:
            self.session_manager.complete_execution(
                execution=execution,
                status=ToolExecutionStatus.FAILED,
                summary=str(e),
            )
            
            # Log activity
            log_user_activity("run_tool", {
                "tool_name": tool_name,
                "execution_id": execution.execution_id,
                "status": "error",
                "error": str(e),
            })
            
            print(f"  ✗ Error: {e}")
            logger.exception("Tool execution failed: %s", tool_name)

    def _print_run_output(self, result: Any, artifacts_before: set[str]) -> None:
        """Show the full rendered output and the files a run produced.

        summarize_for_llm() is capped at the plugin manifest's
        summary_budget because it feeds the LLM context; it is not the user's
        copy of the result.  Tools that
        return a rendering under 'visualization' get it printed in full here,
        and every artifact registered by the run is listed with its path, so
        nothing is lost when the summary is cut short.
        """
        data = result.result or {}
        viz = data.get("visualization")
        if isinstance(viz, str) and viz.strip():
            print("\n  Rendered output:")
            for line in viz.splitlines():
                print(f"  {line}")

        new_artifacts = [
            a for a in self.session_manager.list_artifacts()
            if a.artifact_id not in artifacts_before
        ]
        if new_artifacts:
            print("\n  Output files (use 'show <id>' to print one in full):")
            for a in new_artifacts:
                print(f"    {a.artifact_id:12s} {a.artifact_type:14s} {a.file_path}")

    def do_show(self, arg: str) -> None:
        """Print an artifact's contents in full.

        Usage: show <artifact_id> [max_lines]

        Text, markdown and Mermaid artifacts are printed as-is; JSON is
        pretty-printed.  Use it to see a rendering the run summary cut
        short, or to inspect a tool's JSON output.  Binary artifacts
        (pcap, pdf) are not printed.
        """
        if not self.session_manager.get_current_session():
            print("  No active session. Use 'new' to create one.")
            return

        parts = arg.strip().split()
        if not parts:
            print("  Usage: show <artifact_id> [max_lines]")
            return
        artifact_id = parts[0]
        max_lines: int | None = None
        if len(parts) > 1:
            try:
                max_lines = max(1, int(parts[1]))
            except ValueError:
                print(f"  max_lines must be a number, got {parts[1]!r}")
                return

        art_path = self.session_manager.get_artifact_path(artifact_id)
        if art_path is None:
            print(f"  Artifact not found: {artifact_id}. Use 'artifacts' to list them.")
            return
        art_path = Path(art_path)
        if not art_path.exists():
            print(f"  Artifact file is missing on disk: {art_path}")
            return

        printable = {
            ".txt", ".md", ".mmd", ".json", ".csv", ".log", ".html",
            ".xml", ".stix", ".yaml", ".yml", ".jsonl",
        }
        if art_path.suffix.lower() not in printable:
            print(
                f"  {art_path.name} is not a text artifact "
                f"({art_path.suffix or 'no extension'}); nothing to print."
            )
            return

        try:
            content = art_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"  Could not read {art_path}: {exc}")
            return

        if art_path.suffix.lower() == ".json":
            try:
                content = json.dumps(json.loads(content), indent=2)
            except json.JSONDecodeError:
                pass

        lines = content.splitlines()
        shown = lines if max_lines is None else lines[:max_lines]
        print(f"\n  {artifact_id}  {art_path}  ({len(lines)} lines)\n")
        for line in shown:
            print(f"  {line}")
        if max_lines is not None and len(lines) > max_lines:
            print(f"\n  ... {len(lines) - max_lines} more line(s); "
                  f"run 'show {artifact_id}' without a limit to see all.")
        print()

    def _auto_persist_result(
        self,
        result: Any,
        tool_name: str,
        artifacts_produced: list[str],
    ) -> None:
        """Write a tool's ToolResult.result to disk and register it with the session.

        Called when a tool completes successfully but did not call
        context.register_artifact() itself.  Produces a single output artifact
        whose type is taken from the first entry of the manifest's
        artifacts_produced list (defaulting to 'json_events').

        Text-oriented tools (artifact_type == 'text') receive a .md file whose
        content is the first string field found among common display keys
        (visualization, content, summary, analysis, report, output).
        All other tools receive a .json file containing the full result dict.
        """
        workspace = Path(os.environ.get("EVENTMILL_WORKSPACE", "./workspace"))
        output_dir = workspace / "artifacts"
        output_dir.mkdir(parents=True, exist_ok=True)

        artifact_type = artifacts_produced[0] if artifacts_produced else "json_events"
        result_data = result.result or {}
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Choose format: markdown for text artifacts, JSON for everything else
        if artifact_type == "text":
            text_content: str | None = None
            for key in ("visualization", "content", "summary", "analysis", "report", "output"):
                val = result_data.get(key)
                if isinstance(val, str) and val.strip():
                    text_content = val
                    break
            if text_content is None:
                text_content = json.dumps(result_data, indent=2, default=str)
            content = text_content
            ext = ".md"
        else:
            content = json.dumps(result_data, indent=2, default=str)
            ext = ".json"

        filename = f"{tool_name}_{ts}{ext}"
        output_file = output_dir / filename

        try:
            output_file.write_text(content, encoding="utf-8")
            session_art = self.session_manager.register_artifact(
                artifact_type=artifact_type,
                file_path=str(output_file),
                source_tool=tool_name,
                metadata={"auto_persisted": True},
            )
            logger.info(
                "Auto-persisted output for %s → %s (%s)",
                tool_name, session_art.artifact_id, artifact_type,
            )
        except Exception as exc:
            logger.warning("Auto-persist failed for %s: %s", tool_name, exc)

    def do_tool_history(self, arg: str) -> None:
        """Show tool execution history for the current session.

        Usage: tool_history [--tool <name>] [--status <state>] [--limit <n>] [--detail]
               tool_history <execution_id>

        Statuses: running, completed, failed, timed_out.
        A bare execution id prints that one execution in full.
        """
        if not self.session_manager.get_current_session():
            print("  No active session.")
            return

        stripped = arg.strip()
        exec_id = ""
        detail = False
        tool_filter = ""
        status_filter = ""
        limit = 0

        if stripped and not stripped.startswith("--"):
            parts = stripped.split()
            if len(parts) > 1:
                print("  Usage: tool_history [--tool <name>] [--status <state>] [--limit <n>] [--detail]")
                print("     or: tool_history <execution_id>")
                return
            exec_id = parts[0]
        elif stripped:
            try:
                tokens = shlex.split(stripped)
            except ValueError as e:
                print(f"  Could not parse arguments: {e}")
                return

            pairs, error = _split_flags(tokens)
            if error:
                print(f"  {error}")
                return

            valid_states = [s.value for s in ToolExecutionStatus]
            for key, value in pairs:
                if key == "detail":
                    detail = True
                    continue
                if value is True:
                    print(f"  --{key} needs a value.")
                    return
                if key == "tool":
                    tool_filter = str(value)
                elif key == "status":
                    status_filter = str(value).lower()
                    if status_filter not in valid_states:
                        print(f"  Unknown --status {value!r}. Use {', '.join(valid_states)}.")
                        return
                elif key == "limit":
                    try:
                        limit = int(str(value))
                    except ValueError:
                        print(f"  --limit needs a whole number, got {value!r}.")
                        return
                    if limit < 0:
                        print("  --limit cannot be negative. Use 0 to show all.")
                        return
                else:
                    print(f"  Unknown flag --{key}.")
                    print("  Use --tool, --status, --limit, --detail.")
                    return

        executions = self.session_manager.list_executions()

        if exec_id:
            match = next((e for e in executions if e.execution_id == exec_id), None)
            if match is None:
                print(f"  Execution not found: {exec_id}. Use 'tool_history' to list them.")
                return
            self._print_execution_detail(match)
            return

        if tool_filter:
            executions = [e for e in executions if e.tool_name == tool_filter]
        if status_filter:
            executions = [e for e in executions if e.status.value == status_filter]

        if not executions:
            if tool_filter or status_filter:
                print("  No tool executions match that filter.")
            else:
                print("  No tool executions yet.")
            return

        shown = executions[-limit:] if limit else executions

        if detail:
            for e in shown:
                self._print_execution_detail(e)
        else:
            print(f"  {'ID':14s} {'Tool':24s} {'Status':12s} {'Duration':10s} {'Time':20s}")
            print(f"  {'─' * 14} {'─' * 24} {'─' * 12} {'─' * 10} {'─' * 20}")
            for e in shown:
                time_str = e.started_at.strftime("%Y-%m-%d %H:%M:%S")
                duration = self._execution_duration(e)
                print(
                    f"  {e.execution_id:14s} {e.tool_name:24s} "
                    f"{e.status.value:12s} {duration:10s} {time_str}"
                )

        if limit and len(executions) > len(shown):
            print(f"  {len(shown)} of {len(executions)} executions shown - raise --limit for more.")

    def _print_execution_detail(self, execution: ToolExecution) -> None:
        """Print one tool execution with its artifacts and stored summary."""
        print(f"  [{execution.execution_id}] {execution.tool_name}")
        print(f"    Status:    {execution.status.value} ({self._execution_duration(execution)})")
        print(f"    Started:   {execution.started_at.strftime('%Y-%m-%d %H:%M:%S')}")
        if execution.completed_at:
            print(f"    Finished:  {execution.completed_at.strftime('%Y-%m-%d %H:%M:%S')}")
        if execution.input_artifact_id or execution.output_artifact_id:
            src = execution.input_artifact_id or "-"
            dst = execution.output_artifact_id or "-"
            print(f"    Artifacts: {src} -> {dst}")
        if execution.summary:
            print("    Summary:")
            for line in execution.summary.splitlines():
                print(f"      {line}")
        print()

    @staticmethod
    def _execution_duration(execution: ToolExecution) -> str:
        """Wall-clock time an execution took, or '-' while it is still running."""
        if execution.completed_at is None:
            return "-"
        seconds = (execution.completed_at - execution.started_at).total_seconds()
        if seconds < 60:
            return f"{seconds:.1f}s"
        minutes, secs = divmod(int(seconds), 60)
        return f"{minutes}m{secs:02d}s"

    @staticmethod
    def _turn_time(turn: dict[str, str]) -> datetime | None:
        """Timestamp of an LLM turn, or None for turns recorded without one."""
        raw = turn.get("timestamp")
        if not raw:
            return None
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            return None

    def do_history(self, arg: str) -> None:
        """Show a merged timeline of tool executions and LLM turns.

        Usage: history [--limit <n>]

        One row per event, oldest first. Use 'tool_history' or 'llm_history'
        for the detail behind a row. Tool executions are session state in
        SQLite; LLM turns live in memory for this shell session only.
        """
        stripped = arg.strip()
        if stripped == "clear":
            print("  Only LLM turns can be cleared; tool history is session state.")
            self.do_llm_history("clear")
            return

        limit = HISTORY_DEFAULT_LIMIT
        if stripped:
            try:
                tokens = shlex.split(stripped)
            except ValueError as e:
                print(f"  Could not parse arguments: {e}")
                return

            pairs, error = _split_flags(tokens)
            if error:
                print(f"  {error}")
                return

            for key, value in pairs:
                if key != "limit":
                    print(f"  Unknown flag --{key}. Use --limit.")
                    return
                try:
                    limit = int(str(value))
                except (TypeError, ValueError):
                    print(f"  --limit needs a whole number, got {value!r}.")
                    return
                if limit < 0:
                    print("  --limit cannot be negative. Use 0 to show all.")
                    return

        events: list[tuple[datetime, str, str]] = []

        try:
            executions = self.session_manager.list_executions()
        except ValueError:
            executions = []

        for e in executions:
            events.append((
                e.started_at,
                "tool",
                f"[{e.execution_id}] {e.tool_name} - {e.status.value} "
                f"({self._execution_duration(e)})",
            ))

        for i, turn in enumerate(self._conversation_history, 1):
            question = " ".join(turn["question"].split())
            if len(question) > 62:
                question = question[:59] + "..."
            events.append((self._turn_time(turn) or datetime.max, "llm", f"[{i}] {question}"))

        if not events:
            print("  No history yet. Run a tool, or use 'ask: <question>'.")
            return

        events.sort(key=lambda ev: ev[0])
        shown = events[-limit:] if limit else events

        print(f"  {'Time':20s} {'Kind':6s} Event")
        print(f"  {'─' * 20} {'─' * 6} {'─' * 50}")
        for ts, kind, detail in shown:
            time_str = "-" if ts == datetime.max else ts.strftime("%Y-%m-%d %H:%M:%S")
            print(f"  {time_str:20s} {kind:6s} {detail}")

        tool_count = sum(1 for ev in events if ev[1] == "tool")
        print()
        if limit and len(events) > len(shown):
            print(f"  {len(shown)} of {len(events)} events shown - raise --limit for more.")
        print(
            f"  {tool_count} tool, {len(events) - tool_count} llm. "
            "Detail: 'tool_history', 'llm_history'."
        )
    
    # -------------------------------------------------------------------
    # Route Command
    # -------------------------------------------------------------------
    
    def do_route(self, arg: str) -> None:
        """Show routing decision for a query.
        
        Usage: route <query>
        """
        if not self.router:
            print("  Router not initialized.")
            return
        
        query = arg.strip()
        if not query:
            print("  Usage: route <query>")
            return
        
        session = self.session_manager.get_current_session()
        artifact_types = []
        if self.artifact_registry:
            artifact_types = list(set(
                a.artifact_type for a in self.artifact_registry.list_all()
            ))
        
        result = self.router.route(
            user_input=query,
            artifact_types=artifact_types,
            active_pillar=session.active_pillar if session else None,
        )
        
        print(f"\n  {result.explanation}")
        
        if result.chain_recommendations:
            print(f"\n  Chain recommendations: {', '.join(result.chain_recommendations)}")
    
    # -------------------------------------------------------------------
    # Utility Commands
    # -------------------------------------------------------------------
    
    def do_status(self, arg: str) -> None:
        """Show current investigation status.
        
        Usage: status
        """
        session = self.session_manager.get_current_session()
        if not session:
            print("  No active session. Use 'new' to create one.")
            return
        
        artifacts = self.session_manager.list_artifacts()
        executions = self.session_manager.list_executions()
        completed = sum(
            1 for e in executions
            if e.status == ToolExecutionStatus.COMPLETED
        )
        
        print(f"  Session:    {session.session_id}")
        print(f"  Pillar:     {session.active_pillar or '—'}")
        print(f"  Workspace:  {session.workspace_folder or '—'}")
        print(f"  Artifacts:  {len(artifacts)}")
        print(f"  Executions: {len(executions)} ({completed} completed)")
        print(f"  Created:    {session.created_at.strftime('%Y-%m-%d %H:%M')}")
        print(f"  Updated:    {session.updated_at.strftime('%Y-%m-%d %H:%M')}")
        
        if session.description:
            print(f"  Description: {session.description}")
        
        # Show recent summaries
        summaries = self.session_manager.get_recent_summaries(limit=3)
        if summaries:
            print(f"\n  Recent findings:")
            for s in summaries:
                # Truncate long summaries for display
                display = s[:100] + "..." if len(s) > 100 else s
                print(f"    {display}")
    
    def do_use(self, arg: str) -> None:
        """Choose which LLM provider serves tools.

        Usage: use                              show the current selection
               use <provider>                   session default for every tool
               use <provider> for <tool_name>   override one tool
               use default [for <tool_name>]    clear a selection

        This is the runtime A/B control and the only supported way to point a
        module at a second vendor. Running the same tool on the same input
        under two providers is a deliberate comparison: the prompt stays
        byte-identical across the swap, and every response is stamped with the
        provider that served it.

        The selection lives for this session only. Provider choice is an
        operator decision, so it never reaches plugin code — a plugin cannot
        see it and cannot override it.

        Examples:
          use anthropic for adversary_path_projector
          use openai
          use default for adversary_path_projector
        """
        parts = arg.strip().split()

        if not parts:
            self._show_provider_selection()
            return

        if len(parts) == 1:
            provider_id, tool_name = parts[0], None
        elif len(parts) == 3 and parts[1] == "for":
            provider_id, tool_name = parts[0], parts[2]
        elif len(parts) == 2 and parts[0] == "default" and parts[1] == "for":
            print("  Usage: use default for <tool_name>")
            return
        else:
            print(f"  Unknown argument: {arg.strip()}")
            print("  Usage: use [<provider> | default] [for <tool_name>]")
            return

        if tool_name is not None and not self.plugin_loader.get(tool_name):
            # A typo here would be silent — the override would sit in the map
            # and never match a run.
            print(f"  Tool not found: {tool_name}")
            print("  Use 'tools' to see the tool names.")
            return

        if provider_id == "default":
            if tool_name is None:
                self._provider_default = None
                self._provider_by_tool.clear()
                print("  Cleared. Every tool runs on the session default again.")
            else:
                self._provider_by_tool.pop(tool_name, None)
                print(f"  Cleared the override on {tool_name}.")
            self._show_provider_selection()
            return

        bound = self._bound_providers()
        if not bound:
            print("  No providers are bound. Run 'connect' first.")
            return
        if provider_id not in bound:
            print(f"  Provider not bound: {provider_id}")
            print(f"  Bound: {', '.join(bound)}")
            print("  'providers' shows what is configured; a vendor has to be in")
            print(f"  {llm_factory.PROVIDERS_ENV} and keyed before 'connect' binds it.")
            return

        if tool_name is None:
            self._provider_default = provider_id
            print(f"  Session default: {provider_id}")
            if self._provider_by_tool:
                overridden = ", ".join(sorted(self._provider_by_tool))
                print(f"  Still overridden per tool: {overridden}")
        else:
            self._provider_by_tool[tool_name] = provider_id
            print(f"  {tool_name} will run on {provider_id}.")

    def _show_provider_selection(self) -> None:
        """Print which provider serves tools, and any per-tool overrides."""
        bound = self._bound_providers()
        if not bound:
            print("  No providers are bound. Run 'connect' first.")
            return

        session_default = self._provider_default or getattr(
            self.llm_client, "default_provider", None,
        )
        source = "chosen with 'use'" if self._provider_default else (
            f"first in {llm_factory.PROVIDERS_ENV}"
        )
        print(f"  Session default: {session_default}  ({source})")
        print(f"  Bound:           {', '.join(bound)}")

        if self._provider_by_tool:
            print("")
            print("  Per-tool overrides")
            for tool_name in sorted(self._provider_by_tool):
                print(f"    {tool_name:34s} {self._provider_by_tool[tool_name]}")
        print("")
        print("  'use <provider> for <tool_name>' overrides one tool;")
        print("  'use default' clears every selection.")

    def do_providers(self, arg: str) -> None:
        """Show LLM providers: configured, keyed, and reachable.

        Usage: providers
               providers probe [<provider_id>]

        A mounted key is not a bound provider. The deployment mounts every LLM
        secret for every deployment, with unadopted ones holding a placeholder,
        so 'configured but no key' is an expected state rather than a fault.

        'providers probe' is the only thing here that touches the network: two
        phases per tier, a model listing (no tokens) and a few-token ping.
        'connect' cannot answer either question — every client builds an SDK
        handle and reports success without a round trip, so a wrong key
        connects cleanly and fails later at first use.
        """
        parts = arg.strip().split()
        if parts and parts[0] == "probe":
            self._probe_providers(parts[1] if len(parts) > 1 else None)
            return
        if parts:
            print(f"  Unknown argument: {' '.join(parts)}")
            print("  Usage: providers | providers probe [<provider_id>]")
            return

        rows = llm_factory.provider_status()
        error = next((r["config_error"] for r in rows if r["config_error"]), "")
        if error:
            print(f"  ⚠️  {error}")
            print(f"     Falling back to {llm_factory.PROVIDERS_ENV} unset behaviour.")
            print("")

        print(f"  {'Provider':12s} {'Use':5s} {'Key':16s} {'Light':22s} {'Heavy':22s}")
        print(f"  {'─' * 12} {'─' * 5} {'─' * 16} {'─' * 22} {'─' * 22}")
        for row in rows:
            configured = bool(row["configured"])
            missing = row["missing_keys"]
            if not configured:
                use, key = "—", "—"
            elif missing:
                use, key = "✓", "missing"
            else:
                use, key = "✓", "present"
            if row["is_default"]:
                use = "✓ *"
            tiers = row["tiers"]
            print(
                f"  {str(row['provider_id']):12s} {use:5s} {key:16s} "
                f"{tiers.get('light', '—'):22s} {tiers.get('heavy', '—'):22s}"
            )

        print("")
        for row in rows:
            if row["configured"] and row["missing_keys"]:
                gaps = ", ".join(row["missing_keys"])
                secrets = ", ".join(row["secrets"]) or "—"
                print(f"  {row['provider_id']}: set {gaps} to bind it.")
                print(f"    On Cloud Run that is a new version of: {secrets}")
        unconfigured = [r["provider_id"] for r in rows if not r["configured"]]
        if unconfigured:
            print(
                f"  Not in use: {', '.join(str(p) for p in unconfigured)} — add to "
                f"{llm_factory.PROVIDERS_ENV} (space-separated) to configure."
            )
        print("")
        print("  '*' marks the session default. 'providers probe' checks reachability.")
        print("  'connect' binds every configured provider whose key is present;")
        print("  the default above serves every tool until one is pointed elsewhere.")

    def _probe_providers(self, only: str | None) -> None:
        """Auth + ping every available provider's tiers, and report both phases."""
        try:
            configured = llm_factory.configured_providers()
        except llm_factory.UnknownProviderError as e:
            print(f"  ✗ {e}")
            return

        targets = [only] if only else list(configured)
        unknown = [p for p in targets if p not in llm_factory.known_providers()]
        if unknown:
            print(f"  ✗ unknown provider: {', '.join(unknown)}")
            print(f"    Known: {', '.join(llm_factory.known_providers())}")
            return

        for provider_id in targets:
            print("")
            print(f"  {provider_id}")
            if provider_id not in configured:
                print(
                    f"    · not in {llm_factory.PROVIDERS_ENV} — probing anyway, "
                    "since a key can be verified before it is adopted"
                )
            clients, failures = llm_factory.build_clients(provider_id)
            for message in failures:
                print(f"    ✗ {message}")
            if not clients:
                continue
            for tier in ("light", "heavy"):
                client = clients.get(tier)
                if client is None:
                    continue
                result = client.probe()
                mark = "✓" if result.ok else "✗"
                print(f"    {mark} {tier:6s} {result.model_id}")
                listing = (
                    f"{result.models_listed} models, this one "
                    f"{'visible' if result.model_visible else 'NOT listed'}"
                    if result.auth_ok else result.error[:70]
                )
                print(f"        auth  {listing}")
                if result.auth_ok:
                    if result.ping_ok:
                        served = result.reported_model or "unreported"
                        detail = (
                            f"{result.ping_text[:20]!r} in {result.latency_ms} ms, "
                            f"{result.tokens_used} tokens, served by {served}"
                        )
                        if result.ping_truncated:
                            detail += " — TRUNCATED, raise the budget"
                        print(f"        ping  {detail}")
                    else:
                        print(
                            f"        ping  failed [{result.error_kind}]: "
                            f"{result.error[:70]}"
                        )
        print("")

    def do_models(self, arg: str) -> None:
        """List available LLM models.

        Usage: models
        """
        if not self._available_models:
            print("  No LLM models configured.")
            print("  'providers' lists each configured provider and the key it needs.")
            return
        
        print(f"  {'Model':20s} {'Provider':11s} {'Tier':8s} {'Status':14s} {'ID':30s}")
        print(f"  {'─' * 20} {'─' * 11} {'─' * 8} {'─' * 14} {'─' * 30}")

        for model in self._available_models:
            status = self._model_connected_status(model)
            provider = model.get("provider", DEFAULT_PROVIDER_ID)
            print(
                f"  {model['name']:20s} {provider:11s} {model['tier']:8s} "
                f"{status:14s} {model['id']:30s}"
            )
        
        print("")
        print("  'connect'            — bind all models (tiered auto-routing)")
        print("  'connect <model_id>' — bind a specific model only")
        print("  Routing: plugin manifest model_tier, overridable per call")
        print("           by the plugin; framework calls with no preference")
        print("           use the light tier")
        print("  'providers'          — every provider, keyed or not, and reachability")
        print("  Every provider listed here is bound for tool execution; the first")
        print("  one configured serves any tool that names none.")
    
    def do_connect(self, arg: str) -> None:
        """Connect to LLM.
        
        Usage: connect [model_id]
        
        If no model_id specified, uses the first available model.
        Use 'models' command to see available models.
        """
        if not self._available_models:
            print("  No LLM models configured.")
            print("  'providers' lists each configured provider and the key it needs.")
            return
        
        model_id = arg.strip()

        if not model_id:
            # No model specified — connect every tier of every available
            # provider. Keyed by (provider_id, tier): with two vendors bound a
            # tier alone no longer identifies a client, and a tier-keyed dict
            # would have the second vendor evict the first.
            connected_clients: dict[tuple[str, str], LLMModelClient] = {}
            failed: list[str] = []

            for m in self._available_models:
                provider_id = m.get("provider", DEFAULT_PROVIDER_ID)
                client = self._build_client(m, failed)
                if client is None:
                    continue
                connected_clients[(provider_id, m["tier"])] = client
                print(f"  ✓ {m['name']} ({m['id']})")
                print(f"    Provider: {provider_id}   Tier: {m['tier']}   "
                      f"Key: {m['env_var']}")

            for msg in failed:
                print(msg)
            self._report_dormant_providers(connected_clients)

            if not connected_clients:
                print("  No models connected.")
                return

            self.llm_client = LLMDispatcher(
                clients=connected_clients,
                tier_specs=self._bound_tier_specs(connected_clients),
                preferred_provider=next(iter(connected_clients))[0],
            )

            log_user_activity("connect_llm", {
                "models": {
                    f"{provider_id}/{tier}": c.model_id
                    for (provider_id, tier), c in connected_clients.items()
                },
                "providers": list(self.llm_client.bound_providers()),
                "tiered": True,
            })

            self._prune_provider_selection()
            providers = self.llm_client.bound_providers()
            if len(providers) > 1:
                print("")
                default = self._provider_default or providers[0]
                print(f"  Providers bound: {', '.join(providers)} — "
                      f"'{default}' serves tools by default.")
            if len(connected_clients) > 1:
                print("")
                print("  Auto-routing: each plugin's manifest model_tier, overridable")
                print("                per call; calls with no preference use light")
            return

        # Specific model requested — single-client mode
        selected_model = None
        for m in self._available_models:
            if m["id"] == model_id or m["name"].lower() == model_id.lower():
                selected_model = m
                break
        if not selected_model:
            print(f"  Model not found: {model_id}")
            print("  Use 'models' to see available models.")
            return

        provider_id = selected_model.get("provider", DEFAULT_PROVIDER_ID)
        failures: list[str] = []
        primary_client = self._build_client(selected_model, failures)
        if primary_client is None:
            for msg in failures:
                print(msg)
            self.llm_client = None
            return

        print(f"  ✓ Connected to {selected_model['name']} ({selected_model['id']})")
        print(f"    Provider: {provider_id}   Tier: {selected_model['tier']}   "
              f"Key: {selected_model['env_var']}")

        # Silently try the other tier for quota fallback — of this provider
        # only. LLMDispatcher._fallback_client answers "the other tier of the
        # same provider", so binding another vendor's tier here would offer it
        # a route back to the cross-provider hop that is forbidden.
        connected_clients: dict[tuple[str, str], LLMModelClient] = {
            (provider_id, selected_model["tier"]): primary_client
        }
        other_models = [
            m for m in self._available_models
            if m["tier"] != selected_model["tier"]
            and m.get("provider", DEFAULT_PROVIDER_ID) == provider_id
        ]
        for m in other_models:
            fallback_client = self._build_client(m, [])
            if fallback_client is not None:
                connected_clients[(provider_id, m["tier"])] = fallback_client
                print(f"  ✓ {m['name']} available as quota fallback")

        # Always dispatch, even with a single client. A bare client
        # skips token clamping, the PDF context guard, the retired-model
        # retry, and native document handling entirely.
        self.llm_client = LLMDispatcher(
            clients=connected_clients,
            preferred_tier=selected_model["tier"],
            tier_specs=self._bound_tier_specs(connected_clients),
            preferred_provider=provider_id,
        )

        self._prune_provider_selection()

        log_user_activity("connect_llm", {
            "model_id": selected_model["id"],
            "model_name": selected_model["name"],
            "provider": provider_id,
            "tier": selected_model["tier"],
            "fallback_tiers": [
                tier for (_, tier) in connected_clients
                if tier != selected_model["tier"]
            ],
        })
    
    def do_ask(self, arg: str) -> None:
        """Ask a question about the current investigation using the connected LLM.
        
        Usage: ask: <question>
        
        The colon after 'ask' is required — it signals conscious intent
        to invoke the LLM (which costs tokens and time).
        
        The LLM receives full context from your session: loaded artifacts,
        all tool execution summaries, and prior conversation turns.
        
        Examples:
          ask: what were the usernames targeted in this log file?
          ask: summarize the threat findings so far
          ask: root login is disabled on this server — re-evaluate the threat rating
          ask: search the internet for CVEs related to this SSH pattern
        """
        # Require the colon prefix for conscious intent
        if not arg.startswith(":"):
            print("  Usage: ask: <question>")
            print("  The colon is required to confirm LLM intent.")
            return
        
        question = arg[1:].strip()
        if not question:
            print("  Usage: ask: <question>")
            return
        
        self._query_llm(question)
    
    def _query_llm(self, question: str) -> None:
        """Send a contextual question to the connected LLM and print the response."""
        if not self.llm_client or not self.llm_client.connected:
            print("  No LLM connected. Use 'connect <model_id>' first.")
            print("  Use 'models' to see available models.")
            return
        
        session = self.session_manager.get_current_session()
        if not session:
            print("  No active session. Use 'new' to create one.")
            return
        
        # Build grounding context from session state
        context_parts = self._build_conversation_context(session)
        
        # Include conversation history (last 10 turns)
        history_text = ""
        if self._conversation_history:
            recent = self._conversation_history[-10:]
            history_lines = []
            for turn in recent:
                history_lines.append(f"Analyst: {turn['question']}")
                history_lines.append(f"AI: {turn['answer']}\n")
            history_text = "\n".join(history_lines)
        
        system_context = (
            "You are a Tier 3 SOC analyst assistant embedded in Event Mill, "
            "an event record analysis platform. You have access to the "
            "investigation context below including loaded artifacts and "
            "prior tool execution results. Answer the analyst's questions "
            "thoroughly and specifically based on the evidence available. "
            "When the analyst provides new information (e.g. 'root login is "
            "disabled'), incorporate it to refine your threat assessment. "
            "Reference specific log patterns, IPs, usernames, and counts "
            "from the execution summaries when available. "
            "If asked to search for information or CVEs, use your training "
            "knowledge to provide the most relevant known information."
        )
        
        # Assemble the full prompt
        prompt_parts = []
        if context_parts:
            prompt_parts.append("=== INVESTIGATION CONTEXT ===")
            prompt_parts.append(context_parts)
        if history_text:
            prompt_parts.append("=== CONVERSATION HISTORY ===")
            prompt_parts.append(history_text)
        prompt_parts.append("=== ANALYST QUESTION ===")
        prompt_parts.append(question)
        
        full_prompt = "\n\n".join(prompt_parts)
        
        print("  Thinking...")
        
        try:
            # 'ask:' is analyst-facing reasoning over the full session context —
            # deliberately the heavy tier, not an accident of max_tokens.
            # The session default applies to 'ask:' as well — it is the
            # operator reasoning over their own session, so the vendor they
            # chose is the one that should answer. A per-tool override is not
            # consulted: 'ask:' is not a tool.
            response = self.llm_client.query_text(
                prompt=full_prompt,
                system_context=system_context,
                max_tokens=4096,
                hints=QueryHints(tier="heavy", needs_reasoning=True),
                **self._provider_kwargs(self._provider_default),
            )
            
            if response.ok and response.text:
                # Store in conversation history
                self._conversation_history.append({
                    "question": question,
                    "answer": response.text,
                    "timestamp": datetime.now().isoformat(timespec="seconds"),
                })
                
                # Print the response with indentation
                print("")
                for line in response.text.splitlines():
                    print(f"  {line}")
                print("")
                
                # Show token usage if available
                if response.token_usage:
                    total = response.token_usage.get("total_tokens", 0)
                    if total:
                        print(f"  [{total} tokens used]")
                
                # Log LLM interaction
                log_llm_interaction(
                    prompt=question,
                    response_text=response.text,
                    model_id=self.llm_client.model_id,
                    history_turns=len(self._conversation_history),
                )
            else:
                error = response.error or "Unknown error"
                print(f"  ✗ LLM query failed: {error}")
                log_llm_interaction(
                    prompt=question,
                    response_text=None,
                    model_id=self.llm_client.model_id,
                    history_turns=len(self._conversation_history),
                    error=error,
                )
                
        except Exception as e:
            print(f"  ✗ Error: {e}")
            logger.error("LLM query error: %s", e, exc_info=True)
            log_llm_interaction(
                prompt=question,
                response_text=None,
                model_id=self.llm_client.model_id if self.llm_client else None,
                history_turns=len(self._conversation_history),
                error=str(e),
            )
    
    def _build_conversation_context(self, session) -> str:
        """Assemble investigation context from session state for LLM grounding."""
        parts = []
        
        # Session info
        pillar = session.active_pillar or "none"
        workspace = session.workspace_folder or "default"
        parts.append(f"Session: {session.session_id}")
        parts.append(f"Pillar: {pillar}")
        parts.append(f"Workspace: {workspace}")
        
        # Loaded artifacts
        try:
            artifacts = self.session_manager.list_artifacts()
            if artifacts:
                parts.append("\n--- Loaded Artifacts ---")
                for art in artifacts:
                    fname = art.metadata.get("original_filename", art.file_path)
                    parts.append(f"  [{art.artifact_id}] {art.artifact_type}: {fname}")
        except ValueError:
            pass
        
        # All tool execution summaries (most important context)
        try:
            executions = self.session_manager.list_executions()
            completed = [e for e in executions if e.summary]
            if completed:
                parts.append("\n--- Tool Execution Results ---")
                for ex in completed:
                    parts.append(f"\n[{ex.tool_name}] ({ex.started_at.strftime('%H:%M')}):")
                    parts.append(ex.summary)
        except ValueError:
            pass
        
        return "\n".join(parts)
    
    def do_llm_history(self, arg: str) -> None:
        """Show conversation history with the LLM.

        Usage: llm_history [--last <n>] [--full]
               llm_history clear

        Turns are held in memory for this shell session only; the durable
        record is the structured log.
        """
        stripped = arg.strip()
        if stripped == "clear":
            self._conversation_history.clear()
            print("  Conversation history cleared.")
            return

        last = 0
        full = False
        if stripped:
            try:
                tokens = shlex.split(stripped)
            except ValueError as e:
                print(f"  Could not parse arguments: {e}")
                return

            pairs, error = _split_flags(tokens)
            if error:
                print(f"  {error}")
                return

            for key, value in pairs:
                if key == "full":
                    full = True
                elif key == "last":
                    try:
                        last = int(str(value))
                    except (TypeError, ValueError):
                        print(f"  --last needs a whole number, got {value!r}.")
                        return
                    if last < 0:
                        print("  --last cannot be negative. Use 0 to show all.")
                        return
                else:
                    print(f"  Unknown flag --{key}. Use --last or --full.")
                    return

        if not self._conversation_history:
            print("  No conversation history. Use 'ask: <question>' to start.")
            return

        turns = list(enumerate(self._conversation_history, 1))
        shown = turns[-last:] if last else turns

        for i, turn in shown:
            ts = self._turn_time(turn)
            stamp = f" {ts.strftime('%H:%M:%S')}" if ts else ""
            print(f"  [{i}]{stamp} Q: {turn['question']}")
            answer = turn["answer"]
            if full:
                print("      A:")
                for line in answer.splitlines():
                    print(f"        {line}")
            else:
                flat = " ".join(answer.split())
                preview = flat[:120] + "..." if len(flat) > 120 else flat
                print(f"      A: {preview}")
            print()

        if last and len(turns) > len(shown):
            print(f"  {len(shown)} of {len(turns)} turns shown - raise --last for more.")
    
    def do_exit(self, arg: str) -> bool:
        """Exit Event Mill.
        
        Usage: exit
        """
        # Log activity
        log_user_activity("shell_exit")
        
        print("  Goodbye.")
        return True
    
    def do_quit(self, arg: str) -> bool:
        """Exit Event Mill.
        
        Usage: quit
        """
        return self.do_exit(arg)
    
    def do_EOF(self, arg: str) -> bool:
        """Handle Ctrl+D."""
        print()
        return self.do_exit(arg)
    
    def emptyline(self) -> None:
        """Do nothing on empty input."""
        pass
    
    def default(self, line: str) -> None:
        """Handle unknown commands."""
        stripped = line.strip()
        if stripped.startswith("{"):
            print("  That is a tool payload, not a command — it needs a 'run <tool_name>' prefix:")
            print(f"    run <tool_name> {stripped}")
            print("  Most arguments are easier as flags:")
            print("    run <tool_name> --key value")
            print("  'tools' lists the tool names; 'help <tool_name>' lists its arguments.")
            return
        print(f"  Unknown command: {stripped.split()[0]}")
        print("  Type 'help' for available commands.")
        if self.llm_client and self.llm_client.connected:
            print("  Tip: use 'ask: <question>' to query the LLM.")
    
    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------
    
    def _model_connected_status(self, model: dict) -> str:
        """Return a short status string for a model entry in 'models' output."""
        if self.llm_client is None:
            return ""
        if isinstance(self.llm_client, LLMDispatcher):
            # Provider-qualified: with two vendors bound, a tier alone no
            # longer identifies a client.
            c = self.llm_client.client_at(
                model["tier"], model.get("provider", DEFAULT_PROVIDER_ID),
            )
            return "✓ connected" if (c and c.connected) else ""
        if isinstance(self.llm_client, GeminiClient):
            return "✓ connected" if (self.llm_client.model_id == model["id"] and self.llm_client.connected) else ""
        return ""

    def _infer_artifact_type(self, file_path: Path) -> str:
        """Infer artifact type from file extension.
        
        Handles rotated log files (e.g. auth.log.1, syslog.2.gz) by
        walking the suffix chain from right to left until a known
        extension is found.
        """
        type_map = {
            ".pcap": "pcap",
            ".pcapng": "pcap",
            ".json": "json_events",
            ".log": "log_stream",
            ".txt": "text",
            ".csv": "text",
            ".pdf": "pdf_report",
            ".html": "html_report",
            ".htm": "html_report",
            ".md": "text",
            ".markdown": "text",
            ".docx": "docx_report",
            ".doc": "docx_report",
            ".png": "image",
            ".jpg": "image",
            ".jpeg": "image",
            ".gif": "image",
            ".bmp": "image",
        }
        
        # Walk suffixes right-to-left: .log.1 → try ".1" then ".log"
        for ext in reversed(file_path.suffixes):
            mapped = type_map.get(ext.lower())
            if mapped:
                return mapped
        
        return "text"


def main() -> None:
    """Entry point for the Event Mill CLI."""
    # Setup logging
    log_level = os.environ.get("EVENTMILL_LOG_LEVEL", "INFO")
    workspace = Path(
        os.environ.get("EVENTMILL_WORKSPACE", "./workspace")
    )
    log_file = workspace / "logs" / "eventmill.log"
    
    # Cloud Run sets K_SERVICE env var — use JSON logging for Cloud Logging
    is_cloud_run = os.environ.get("K_SERVICE") is not None

    # Local development: read .env from the working directory so API keys do
    # not have to be exported by hand. Never on Cloud Run, where the same
    # variables arrive from Secret Manager via --set-secrets and a stray file
    # must not shadow them. override=False means a variable already in the
    # environment always wins, on either path.
    dotenv_path: Path | None = None
    if not is_cloud_run:
        from dotenv import find_dotenv, load_dotenv

        found = find_dotenv(usecwd=True)
        if found and load_dotenv(found, override=False):
            dotenv_path = Path(found)

    setup_logging(
        log_level=log_level,
        log_file=log_file,
        console=True,
        cloud_json=is_cloud_run,
    )

    if dotenv_path is not None:
        logger.info("Loaded local environment from %s", dotenv_path)

    # Gracefully handle SIGHUP (signal 1) — sent by ttyd when a browser
    # tab closes or Cloud Run manages instance lifecycle. Without this,
    # the Python process crashes with "Uncaught signal: 1".
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, lambda signum, frame: sys.exit(0))
    
    try:
        shell = EventMillShell()
        shell.cmdloop()
    except KeyboardInterrupt:
        print("\n  Interrupted. Goodbye.")
        sys.exit(0)


if __name__ == "__main__":
    main()
