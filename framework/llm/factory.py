"""
Event Mill LLM Provider Registry

Which providers exist, which of them this session may use, and how to build
their clients. One place, so a new vendor is a registry entry plus a manifest
rather than a change to the shell.

Three states, and keeping them apart is the point of this module:

    known       the framework has a client for it
    configured  EVENTMILL_LLM_PROVIDERS names it — the operator intends to use it
    available   configured AND its key is present and not a placeholder

A mounted key is not a bound provider, and a configured provider is not an
available one. The deployment provisions and mounts every LLM secret for every
deployment, with the unadopted ones holding the literal "placeholder", so
"configured but unavailable" is the expected steady state rather than a fault.

Clients are imported lazily. Importing one imports its vendor SDK, so a
provider whose extra is not installed must not break a session on a provider
whose extra is.
"""

from __future__ import annotations

import importlib
import logging
import os
from typing import TYPE_CHECKING

from .providers import DEFAULT_PROVIDER_ID, load_tier_specs

if TYPE_CHECKING:  # pragma: no cover — import cycle otherwise
    from .model_client import LLMModelClient

logger = logging.getLogger("eventmill.framework.llm.factory")

# provider_id -> (module, class). Must stay in step with the provider ids
# cloud_install/deploy-cloudrun-secrets.sh accepts, or a provider that deploys
# will not bind and one that binds will not deploy.
PROVIDER_CLIENTS: dict[str, tuple[str, str]] = {
    "gcp_gemini": ("framework.llm.clients.gemini", "GeminiClient"),
    "anthropic": ("framework.llm.clients.anthropic", "AnthropicClient"),
    "openai": ("framework.llm.clients.openai", "OpenAIClient"),
}

# Names the deploy path uses for each provider's secret, for error messages that
# tell an operator what to fix rather than only what broke.
PROVIDER_SECRETS: dict[str, tuple[str, ...]] = {
    "gcp_gemini": ("eventmill-gemini-flash-api", "eventmill-gemini-pro-api"),
    "anthropic": ("eventmill-anthropic-api",),
    "openai": ("eventmill-openai-api",),
}

# What to pip install to get a provider's SDK. Not derivable from the provider
# id: google-genai is a base dependency rather than an extra, and one SDK can
# serve several providers — a specialist model on its own key is still the
# openai package. Deriving it from the id told operators to install extras that
# do not exist.
PROVIDER_SDK_INSTALL: dict[str, str] = {
    "gcp_gemini": "eventmill",
    "anthropic": "eventmill[llm-anthropic]",
    "openai": "eventmill[llm-openai]",
}

PROVIDERS_ENV = "EVENTMILL_LLM_PROVIDERS"

# The value an unadopted provider's secret holds. provision-gcp-project.sh
# writes it so every deployment mounts the same secret set; it is not a key.
PLACEHOLDER = "placeholder"


class UnknownProviderError(ValueError):
    """A provider id the framework has no client for.

    Raised rather than skipped: a typo in EVENTMILL_LLM_PROVIDERS would
    otherwise leave that provider silently absent, which looks like a working
    session until a tool tries to use it. The deploy script refuses the same
    way, and for the same reason.
    """


def known_providers() -> tuple[str, ...]:
    """Provider ids the framework has a client for."""
    return tuple(PROVIDER_CLIENTS)


def configured_providers(raw: str | None = None) -> tuple[str, ...]:
    """Provider ids this session may bind, from EVENTMILL_LLM_PROVIDERS.

    Space-separated, defaulting to EVERY known provider. Order is preserved:
    the first entry is the session default, so the default order also decides
    which vendor serves a tool that names none.

    Defaulting to all of them rather than to Gemini alone is deliberate.
    Naming a provider costs nothing when its key is absent — build_clients and
    _discover_models both skip a key that is unset or still holds the
    placeholder — whereas leaving one out means a vendor whose key IS present
    never binds, and the symptom is a vendor that is simply missing rather than
    an error. That failure has happened; the reverse has not.

    Raises UnknownProviderError naming the unknown id and the known set.
    """
    value = raw if raw is not None else os.environ.get(PROVIDERS_ENV, "")
    ids = tuple(dict.fromkeys(value.split())) or known_providers()
    unknown = [p for p in ids if p not in PROVIDER_CLIENTS]
    if unknown:
        raise UnknownProviderError(
            f"unknown provider id(s) in {PROVIDERS_ENV}: {', '.join(unknown)} — "
            f"known: {', '.join(known_providers())}"
        )
    return ids


def key_env_vars(provider_id: str) -> tuple[str, ...]:
    """Env vars holding this provider's keys, in tier order.

    Gemini declares one per tier so bulk Flash work cannot consume Pro quota;
    Anthropic and OpenAI declare the same var on both tiers because neither
    vendor splits keys by tier. Deduplicated, so this is the set to check.
    """
    specs = load_tier_specs(provider_id)
    seen: list[str] = []
    for tier in ("light", "heavy"):
        spec = specs.get(tier)
        if spec and spec.api_key_env and spec.api_key_env not in seen:
            seen.append(spec.api_key_env)
    return tuple(seen)


def missing_keys(provider_id: str) -> tuple[str, ...]:
    """Env vars this provider needs that are unset or hold the placeholder."""
    missing = []
    for env_var in key_env_vars(provider_id):
        value = (os.environ.get(env_var) or "").strip()
        if not value or value == PLACEHOLDER:
            missing.append(env_var)
    return tuple(missing)


def provider_status(raw: str | None = None) -> list[dict[str, object]]:
    """What every known provider's situation is, for the CLI to render.

    Reports on all known providers, not only the configured ones: an operator
    asking why a vendor is not there needs to see it listed as unconfigured
    rather than absent from the table.
    """
    try:
        configured = configured_providers(raw)
        bad = ""
    except UnknownProviderError as e:
        configured = (DEFAULT_PROVIDER_ID,)
        bad = str(e)

    rows: list[dict[str, object]] = []
    for provider_id in known_providers():
        specs = load_tier_specs(provider_id)
        gaps = missing_keys(provider_id)
        rows.append({
            "provider_id": provider_id,
            "configured": provider_id in configured,
            "is_default": bool(configured) and provider_id == configured[0],
            "key_env_vars": key_env_vars(provider_id),
            "missing_keys": gaps,
            "available": provider_id in configured and not gaps,
            "tiers": {t: s.model_id for t, s in specs.items()},
            "secrets": PROVIDER_SECRETS.get(provider_id, ()),
            "config_error": bad,
        })
    return rows


def available_providers(raw: str | None = None) -> tuple[str, ...]:
    """Configured providers whose keys are actually present.

    A configured provider missing its key is a warning, not a failure: a
    placeholder-seeded deployment is the expected steady state, and refusing to
    start over one would make adopting a vendor a deployment event.
    """
    out = []
    for row in provider_status(raw):
        if not row["configured"]:
            continue
        if row["available"]:
            out.append(str(row["provider_id"]))
        else:
            gaps = ", ".join(row["missing_keys"])  # type: ignore[arg-type]
            logger.warning(
                "Provider %s is configured but has no key: %s unset or "
                "placeholder. It will not bind.", row["provider_id"], gaps,
            )
    return tuple(out)


def sdk_install_target(provider_id: str) -> str:
    """Pip target that installs this provider's SDK, for an ImportError message.

    Falls back to the everything extra for a provider the map has not been
    told about: an install line that over-installs is recoverable, one naming
    an extra that does not exist is not.
    """
    return PROVIDER_SDK_INSTALL.get(provider_id, "eventmill[all]")


def client_class(provider_id: str) -> type:
    """Import and return a provider's client class.

    Lazy by design: importing a client imports its vendor SDK, so this is where
    a missing extra surfaces — as a named ImportError for one provider, not a
    failure to load the module for all of them.
    """
    if provider_id not in PROVIDER_CLIENTS:
        raise UnknownProviderError(
            f"unknown provider id {provider_id!r} — "
            f"known: {', '.join(known_providers())}"
        )
    module_path, class_name = PROVIDER_CLIENTS[provider_id]
    module = importlib.import_module(module_path)
    return getattr(module, class_name)


def build_clients(
    provider_id: str, connect: bool = True,
) -> tuple[dict[str, "LLMModelClient"], list[str]]:
    """Build one client per declared tier of a provider.

    Returns (clients keyed by tier, failure messages). A tier whose key is
    absent is skipped with a message rather than raising: one tier reachable is
    a usable session, and it is how a Gemini setup with only a Flash key
    already behaves.

    ``connect=False`` builds without establishing a session, for a caller that
    wants to inspect the wiring without touching the network.
    """
    clients: dict[str, LLMModelClient] = {}
    failures: list[str] = []

    try:
        cls = client_class(provider_id)
    except ImportError as e:
        failures.append(
            f"{provider_id}: SDK not installed ({e}) — "
            f"pip install '{sdk_install_target(provider_id)}'"
        )
        return clients, failures

    specs = load_tier_specs(provider_id)
    if not specs:
        failures.append(f"{provider_id}: no tiers declared in its manifest")
        return clients, failures

    for tier in ("light", "heavy"):
        spec = specs.get(tier)
        if not spec:
            continue
        if not spec.api_key_env:
            failures.append(f"{provider_id}/{tier}: manifest declares no api_key_env")
            continue
        api_key = (os.environ.get(spec.api_key_env) or "").strip()
        if not api_key or api_key == PLACEHOLDER:
            failures.append(
                f"{provider_id}/{tier}: {spec.api_key_env} unset or placeholder"
            )
            continue
        client = cls(
            model_id=spec.model_id, tier=tier, api_key_env_var=spec.api_key_env,
            provider_id=provider_id,
        )
        if not connect:
            clients[tier] = client
            continue
        if client.connect(api_key=api_key):
            clients[tier] = client
        else:
            failures.append(
                f"{provider_id}/{tier}: connect failed for {spec.model_id}"
            )
    return clients, failures


__all__ = [
    "PLACEHOLDER",
    "PROVIDERS_ENV",
    "PROVIDER_CLIENTS",
    "PROVIDER_SDK_INSTALL",
    "PROVIDER_SECRETS",
    "UnknownProviderError",
    "available_providers",
    "build_clients",
    "client_class",
    "configured_providers",
    "key_env_vars",
    "known_providers",
    "missing_keys",
    "provider_status",
    "sdk_install_target",
]
