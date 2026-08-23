"""
Event Mill LLM Provider Manifests

JSON capability manifests for each supported cloud provider.
Declares, per tier, the model id, API-key environment variable, and output
token cap. Loaded by the CLI when building the available-model list and by
the LLMDispatcher when clamping max_tokens to the selected tier.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger("eventmill.framework.llm.providers")

DEFAULT_PROVIDER_ID = "gcp_gemini"

# Env vars that override the manifest's model id for a tier.
TIER_MODEL_ENV_OVERRIDE = {
    "light": "EVENTMILL_MODEL_LIGHT",
    "heavy": "EVENTMILL_MODEL_HEAVY",
}

# Caps used when no provider manifest is available. Gemini 3.x tiers are
# capacity-identical (1,048,576 in / 65,536 out) — tier is quality/cost, not size.
_FALLBACK_MAX_OUTPUT_TOKENS = {"light": 65536, "heavy": 65536}


@dataclass(frozen=True)
class TierSpec:
    """Resolved configuration for one model tier."""

    tier: str
    model_id: str
    api_key_env: str
    max_output_tokens: int
    max_context_tokens: int
    cost_tier: str
    capabilities: tuple[str, ...]
    display_name: str = ""
    # Model to retry against when model_id is retired (Preview endpoints).
    # Empty means no fallback — the call fails and the caller decides.
    fallback_model_id: str = ""

    def label(self) -> str:
        """Human-readable name for CLI listings."""
        return self.display_name or self.model_id


def manifest_path(provider_id: str = DEFAULT_PROVIDER_ID) -> Path:
    """Path to a provider's capability manifest."""
    return Path(__file__).parent / f"{provider_id}.json"


def load_provider_manifest(
    provider_id: str = DEFAULT_PROVIDER_ID,
) -> dict[str, Any] | None:
    """Load and parse a provider capability manifest.

    Returns None (and logs) if the manifest is missing or malformed —
    callers fall back to built-in defaults rather than failing to start.
    """
    path = manifest_path(provider_id)
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning("Provider manifest not found: %s", path)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Provider manifest %s unreadable: %s", path, e)
    return None


def load_tier_specs(
    provider_id: str = DEFAULT_PROVIDER_ID,
) -> dict[str, TierSpec]:
    """Resolve every declared tier for a provider.

    Model ids may be overridden per tier via EVENTMILL_MODEL_LIGHT /
    EVENTMILL_MODEL_HEAVY, so an operator can point a tier at a different
    model without editing the manifest.

    Returns an empty dict when the manifest cannot be loaded.
    """
    manifest = load_provider_manifest(provider_id)
    if not manifest:
        return {}

    specs: dict[str, TierSpec] = {}
    for tier, cfg in (manifest.get("tiers") or {}).items():
        model_id = cfg.get("model_id", "")
        override_env = TIER_MODEL_ENV_OVERRIDE.get(tier)
        if override_env:
            model_id = os.environ.get(override_env) or model_id
        if not model_id:
            logger.warning("Provider %s tier %s has no model_id", provider_id, tier)
            continue
        specs[tier] = TierSpec(
            tier=tier,
            model_id=model_id,
            api_key_env=cfg.get("api_key_env", ""),
            max_output_tokens=cfg.get(
                "max_output_tokens", _FALLBACK_MAX_OUTPUT_TOKENS.get(tier, 8192),
            ),
            max_context_tokens=cfg.get("max_context_tokens", 1_048_576),
            cost_tier=cfg.get("cost_tier", "low"),
            capabilities=tuple(cfg.get("capabilities", [])),
            display_name=cfg.get("display_name", ""),
            fallback_model_id=cfg.get("fallback_model_id", ""),
        )
    return specs


# Per-page PDF token cost by media_resolution, used when the provider manifest
# is unavailable. Gemini 3.x: native text is free; these are the image tokens.
_FALLBACK_TOKENS_PER_PAGE = {"low": 280, "medium": 560, "high": 1120}
DEFAULT_MEDIA_RESOLUTION = "medium"


def pdf_handling(provider_id: str = DEFAULT_PROVIDER_ID) -> dict[str, Any]:
    """PDF limits for a provider: page/size caps and per-resolution page cost."""
    manifest = load_provider_manifest(provider_id) or {}
    return (manifest.get("file_handling") or {}).get("application/pdf", {})


def default_media_resolution(provider_id: str = DEFAULT_PROVIDER_ID) -> str:
    """Media resolution used for PDFs when the caller does not specify one."""
    return pdf_handling(provider_id).get(
        "default_media_resolution", DEFAULT_MEDIA_RESOLUTION,
    )


def tokens_per_pdf_page(
    resolution: str | None = None, provider_id: str = DEFAULT_PROVIDER_ID,
) -> int:
    """Token cost of one PDF page at a given media_resolution.

    Under Gemini 3.x this is set by media_resolution, not a fixed constant:
    low=280, medium=560 (default), high=1120 — plus native text, which is free.
    """
    handling = pdf_handling(provider_id)
    res = resolution or handling.get(
        "default_media_resolution", DEFAULT_MEDIA_RESOLUTION,
    )
    by_res = handling.get("tokens_per_page_by_resolution") or {}
    if res in by_res:
        return by_res[res]
    if res in _FALLBACK_TOKENS_PER_PAGE:
        return _FALLBACK_TOKENS_PER_PAGE[res]
    return handling.get("tokens_per_page", _FALLBACK_TOKENS_PER_PAGE["medium"])


def max_output_tokens_for_tier(
    tier: str, provider_id: str = DEFAULT_PROVIDER_ID,
) -> int:
    """Output-token cap for a tier, with a conservative built-in fallback."""
    spec = load_tier_specs(provider_id).get(tier)
    if spec:
        return spec.max_output_tokens
    return _FALLBACK_MAX_OUTPUT_TOKENS.get(tier, 8192)


__all__ = [
    "DEFAULT_MEDIA_RESOLUTION",
    "DEFAULT_PROVIDER_ID",
    "TierSpec",
    "load_provider_manifest",
    "load_tier_specs",
    "manifest_path",
    "max_output_tokens_for_tier",
    "pdf_handling",
    "default_media_resolution",
    "tokens_per_pdf_page",
]
