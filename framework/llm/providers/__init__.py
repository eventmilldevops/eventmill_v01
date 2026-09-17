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
from functools import lru_cache
from pathlib import Path
from typing import Any

logger = logging.getLogger("eventmill.framework.llm.providers")

DEFAULT_PROVIDER_ID = "gcp_gemini"

# Env vars that override the manifest's model id for a tier.
#
# These are UNQUALIFIED and apply to the default provider only. With one
# provider that was complete; with three, a global EVENTMILL_MODEL_HEAVY would
# point every provider's heavy tier at one vendor's model id — .env pins
# gemini-3.1-pro-preview today, which would have retargeted Anthropic's heavy
# tier at a Gemini model the moment anthropic.json loaded. Other providers use
# the qualified form below.
TIER_MODEL_ENV_OVERRIDE = {
    "light": "EVENTMILL_MODEL_LIGHT",
    "heavy": "EVENTMILL_MODEL_HEAVY",
}

# Paired with the above: a substitute model rarely shares the manifest model's
# output cap, and clamping against the wrong cap fails at the provider.
TIER_MAX_OUTPUT_ENV_OVERRIDE = {
    "light": "EVENTMILL_MAX_OUTPUT_LIGHT",
    "heavy": "EVENTMILL_MAX_OUTPUT_HEAVY",
}


def _env_provider_token(provider_id: str) -> str:
    """Provider id as it appears in an env var name: gcp_gemini -> GCP_GEMINI."""
    return "".join(c if c.isalnum() else "_" for c in provider_id).upper()


def _model_override_env(provider_id: str, tier: str) -> str | None:
    """Env var that overrides this provider's model id for this tier.

    Qualified for every provider (EVENTMILL_MODEL_ANTHROPIC_HEAVY); the
    unqualified EVENTMILL_MODEL_HEAVY is honoured for the default provider
    only, so an existing .env keeps working without reaching other vendors.
    """
    if provider_id == DEFAULT_PROVIDER_ID:
        return TIER_MODEL_ENV_OVERRIDE.get(tier)
    if tier not in TIER_MODEL_ENV_OVERRIDE:
        return None
    return f"EVENTMILL_MODEL_{_env_provider_token(provider_id)}_{tier.upper()}"


def _max_output_override_env(provider_id: str, tier: str) -> str | None:
    """Env var that overrides this provider's output cap for this tier."""
    if provider_id == DEFAULT_PROVIDER_ID:
        return TIER_MAX_OUTPUT_ENV_OVERRIDE.get(tier)
    if tier not in TIER_MAX_OUTPUT_ENV_OVERRIDE:
        return None
    return f"EVENTMILL_MAX_OUTPUT_{_env_provider_token(provider_id)}_{tier.upper()}"

# Caps used when no provider manifest is available. Gemini 3.x tiers are
# capacity-identical (1,048,576 in / 65,536 out) — tier is quality/cost, not size.
_DEFAULT_MAX_OUTPUT_TOKENS = 65536
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
    # Reasoning-depth levels this tier accepts, most shallow first. Empty means
    # the manifest declares none and every level in the provider's output
    # budget is assumed accepted. Not every provider takes the same set:
    # gemini-3.8-flash and both gpt-5.6 models reject "minimal" outright, so a
    # level that is valid vocabulary in QueryHints can still be a 400.
    thinking_levels: tuple[str, ...] = ()
    provider_id: str = DEFAULT_PROVIDER_ID

    def label(self) -> str:
        """Human-readable name for CLI listings."""
        return self.display_name or self.model_id


def manifest_path(provider_id: str = DEFAULT_PROVIDER_ID) -> Path:
    """Path to a provider's capability manifest."""
    return Path(__file__).parent / f"{provider_id}.json"


@lru_cache(maxsize=16)
def load_provider_manifest(
    provider_id: str = DEFAULT_PROVIDER_ID,
) -> dict[str, Any] | None:
    """Load and parse a provider capability manifest.

    Returns None (and logs) if the manifest is missing or malformed —
    callers fall back to built-in defaults rather than failing to start.

    Cached: the PDF guard alone consults it several times per call, and the
    manifest does not change while the process runs. Call
    load_provider_manifest.cache_clear() if a test rewrites the file.
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


def vendor_of(provider_id: str = DEFAULT_PROVIDER_ID) -> str:
    """Which lab's model a provider serves.

    Deliberately distinct from provider_id. Two providers can reach two
    different models on two different keys and still be one vendor — which is
    what happens the moment a lab's specialist model is adopted alongside its
    general one. Anything measuring how far a finding's support extends has to
    count these rather than provider ids, or one lab's two models read as two
    independent opinions.

    Falls back to the provider id, which is the right answer for every
    provider that is its own vendor and for a manifest that cannot be read.
    """
    manifest = load_provider_manifest(provider_id) or {}
    return str(manifest.get("vendor") or "") or provider_id


def load_tier_specs(
    provider_id: str = DEFAULT_PROVIDER_ID,
) -> dict[str, TierSpec]:
    """Resolve every declared tier for a provider.

    Model ids may be overridden per tier via EVENTMILL_MODEL_LIGHT /
    EVENTMILL_MODEL_HEAVY for the default provider, or the provider-qualified
    EVENTMILL_MODEL_<PROVIDER>_<TIER> for any provider, so an operator can
    point a tier at a different model without editing the manifest.

    Returns an empty dict when the manifest cannot be loaded.
    """
    manifest = load_provider_manifest(provider_id)
    if not manifest:
        return {}

    specs: dict[str, TierSpec] = {}
    for tier, cfg in (manifest.get("tiers") or {}).items():
        model_id = cfg.get("model_id", "")
        override_env = _model_override_env(provider_id, tier)
        overridden = False
        if override_env and os.environ.get(override_env):
            # An override naming the manifest's own model is a redundant pin,
            # not a substitution — warning about its output cap would be noise
            # on every start.
            overridden = os.environ[override_env] != model_id
            model_id = os.environ[override_env]
        if not model_id:
            logger.warning("Provider %s tier %s has no model_id", provider_id, tier)
            continue
        max_output = cfg.get(
            "max_output_tokens",
            _FALLBACK_MAX_OUTPUT_TOKENS.get(tier, _DEFAULT_MAX_OUTPUT_TOKENS),
        )
        cap_env = _max_output_override_env(provider_id, tier)
        cap_raw = os.environ.get(cap_env) if cap_env else None
        if cap_raw:
            try:
                max_output = int(cap_raw)
            except ValueError:
                logger.warning("%s=%r is not an integer — ignoring", cap_env, cap_raw)
        elif overridden:
            logger.warning(
                "%s pins tier %s to %s, but the output cap still comes from the "
                "manifest (%d). Set %s if the substitute model differs.",
                override_env, tier, model_id, max_output, cap_env,
            )
        specs[tier] = TierSpec(
            tier=tier,
            model_id=model_id,
            api_key_env=cfg.get("api_key_env", ""),
            max_output_tokens=max_output,
            max_context_tokens=cfg.get("max_context_tokens", 1_048_576),
            cost_tier=cfg.get("cost_tier", "low"),
            capabilities=tuple(cfg.get("capabilities", [])),
            display_name=cfg.get("display_name", ""),
            fallback_model_id=cfg.get("fallback_model_id", ""),
            thinking_levels=tuple(cfg.get("thinking_levels", [])),
            provider_id=provider_id,
        )
    return specs


# Per-page PDF token cost by media_resolution, used when the provider manifest
# is unavailable. Gemini 3.x: native text is free; these are the image tokens.
_FALLBACK_TOKENS_PER_PAGE = {"low": 280, "medium": 560, "high": 1120}
DEFAULT_MEDIA_RESOLUTION = "medium"

# Thinking tokens come out of max_output_tokens on Gemini 3.x; these are the
# reserves used when the provider manifest declares none.
_FALLBACK_THINKING_RESERVE = {
    "minimal": 1024, "low": 4096, "medium": 16384, "high": 32768,
}
DEFAULT_THINKING_LEVEL = "medium"


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


def thinking_reserve_tokens(
    thinking_level: str | None = None, provider_id: str = DEFAULT_PROVIDER_ID,
) -> int:
    """Output tokens to hold back for reasoning at a given thinking_level.

    Gemini 3.x spends thinking tokens from the same budget as the reply, so a
    caller that sizes a reply against the full ``max_output_tokens`` gets it
    cut off mid-record. Subtract this first; the remainder is what the model
    can actually spend on content.
    """
    budget = (load_provider_manifest(provider_id) or {}).get("output_budget") or {}
    level = thinking_level or budget.get(
        "default_thinking_level", DEFAULT_THINKING_LEVEL,
    )
    reserves = budget.get("thinking_reserve_tokens") or _FALLBACK_THINKING_RESERVE
    if level in reserves:
        return reserves[level]
    return _FALLBACK_THINKING_RESERVE.get(level, _FALLBACK_THINKING_RESERVE["medium"])


def max_output_tokens_for_tier(
    tier: str, provider_id: str = DEFAULT_PROVIDER_ID,
) -> int:
    """Declared output-token cap of a tier, or the built-in default."""
    spec = load_tier_specs(provider_id).get(tier)
    return spec.max_output_tokens if spec else _DEFAULT_MAX_OUTPUT_TOKENS


# Shallowest to deepest. Not every provider accepts every level — the manifest's
# per-tier thinking_levels is what says which — but where two providers share a
# name they mean the same relative depth, so this is the order to pick from.
_LEVEL_ORDER = ("minimal", "low", "medium", "high", "xhigh", "max")

# Content allowance on top of the thinking reserve for a probe's ping. The ping
# asks for one word; this only has to cover it.
PING_CONTENT_TOKENS = 64


def accepted_thinking_levels(
    tier: str, provider_id: str = DEFAULT_PROVIDER_ID,
) -> tuple[str, ...]:
    """Reasoning-depth levels a tier accepts, shallowest first.

    A level that is valid QueryHints vocabulary can still be a 400 at the
    provider: gemini-3.8-flash and both gpt-5.6 models reject "minimal". Where
    the manifest declares nothing, fall back to the levels its output budget
    prices, which is the widest set that can be costed.
    """
    spec = load_tier_specs(provider_id).get(tier)
    declared = spec.thinking_levels if spec else ()
    if not declared:
        budget = (load_provider_manifest(provider_id) or {}).get("output_budget") or {}
        reserves = budget.get("thinking_reserve_tokens") or _FALLBACK_THINKING_RESERVE
        declared = tuple(reserves)
    return tuple(lv for lv in _LEVEL_ORDER if lv in declared)


def ping_budget(
    tier: str, provider_id: str = DEFAULT_PROVIDER_ID,
) -> tuple[int, str | None]:
    """Output budget and reasoning level for a liveness ping.

    Returns (max_output_tokens, thinking_level). A flat small budget does not
    work: reasoning is spent from the output budget, and the spend varies
    between identical calls — gemini-3.8-flash returned empty text at a
    64-token cap on one run and "OK" on the next, and gpt-5-mini spent all 64
    tokens on reasoning. So size the ping from the reserve the provider
    declares for its shallowest accepted level. The budget is a ceiling rather
    than a charge, so reserving generously costs nothing unless it is spent.
    """
    levels = accepted_thinking_levels(tier, provider_id)
    level = levels[0] if levels else None
    reserve = thinking_reserve_tokens(level, provider_id)
    cap = max_output_tokens_for_tier(tier, provider_id)
    return min(reserve + PING_CONTENT_TOKENS, cap), level


__all__ = [
    "DEFAULT_MEDIA_RESOLUTION",
    "DEFAULT_THINKING_LEVEL",
    "DEFAULT_PROVIDER_ID",
    "PING_CONTENT_TOKENS",
    "TierSpec",
    "accepted_thinking_levels",
    "ping_budget",
    "load_provider_manifest",
    "load_tier_specs",
    "manifest_path",
    "pdf_handling",
    "default_media_resolution",
    "max_output_tokens_for_tier",
    "thinking_reserve_tokens",
    "tokens_per_pdf_page",
    "vendor_of",
]
