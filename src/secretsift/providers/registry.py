"""Provider factory: build providers from a type name or a config mapping.

Config keys per type (unknown keys are rejected; API keys are never accepted inline, only the
name of an environment variable via ``api_key_env``):

* ``mock``: ``behavior``, ``script``, ``chunk_size``, ``model``
* ``openai_compatible``: ``base_url`` (required), ``api_key_env``, ``model``, ``timeout``
* ``openai`` / ``anthropic`` / ``gemini``: ``base_url``, ``api_key_env``, ``model``, ``timeout``
* ``llama_cpp`` / ``ollama``: ``base_url``, ``model``, ``timeout``
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from secretsift.exceptions import ConfigError
from secretsift.providers.anthropic import AnthropicProvider
from secretsift.providers.base import Provider, ProviderStatus
from secretsift.providers.gemini import GeminiProvider
from secretsift.providers.llama_cpp import LlamaCppProvider
from secretsift.providers.mock import MockProvider
from secretsift.providers.ollama import OllamaProvider
from secretsift.providers.openai import OpenAIProvider
from secretsift.providers.openai_compatible import OpenAICompatibleProvider
from secretsift.providers.transport import Transport

_COMMON = {"type", "name", "model", "timeout", "base_url"}
_KEYED = _COMMON | {"api_key_env"}
_ALLOWED: dict[str, frozenset[str]] = {
    "mock": frozenset({"type", "name", "model", "behavior", "script", "chunk_size"}),
    "openai_compatible": frozenset(_KEYED),
    "openai": frozenset(_KEYED),
    "anthropic": frozenset(_KEYED),
    "gemini": frozenset(_KEYED),
    "llama_cpp": frozenset(_COMMON),
    "ollama": frozenset(_COMMON),
}
_HTTP_CLASSES: dict[str, Callable[..., Provider]] = {
    "openai_compatible": OpenAICompatibleProvider,
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
    "gemini": GeminiProvider,
    "llama_cpp": LlamaCppProvider,
    "ollama": OllamaProvider,
}


def available_provider_types() -> list[str]:
    """Sorted names accepted as ``type``."""
    return sorted(_ALLOWED)


def create_provider(
    name_or_cfg: str | Mapping[str, Any],
    config: Mapping[str, Any] | None = None,
    *,
    transport: Transport | None = None,
) -> Provider:
    """Build a provider from a config name (looked up in ``config``), a type name or a dict."""
    if isinstance(name_or_cfg, str):
        cfg_name = name_or_cfg
        if config is not None and cfg_name in config:
            raw: Any = config[cfg_name]
        elif cfg_name in _ALLOWED:
            raw = {"type": cfg_name}
        else:
            raise ConfigError(f"unknown provider {cfg_name!r}")
        if not isinstance(raw, Mapping):
            raise ConfigError(f"provider config {cfg_name!r} must be a mapping")
        cfg = dict(raw)
        cfg.setdefault("name", cfg_name)
    elif isinstance(name_or_cfg, Mapping):
        cfg = dict(name_or_cfg)
    else:
        raise ConfigError("provider must be a name or a mapping with a 'type'")

    ptype = cfg.get("type")
    if not isinstance(ptype, str) or ptype not in _ALLOWED:
        raise ConfigError(f"provider type must be one of: {', '.join(available_provider_types())}")
    unknown = sorted(str(k) for k in cfg if k not in _ALLOWED[ptype])
    if unknown:
        raise ConfigError(f"unknown option(s) for provider type {ptype}: {', '.join(unknown)}")
    name = cfg.get("name", ptype)
    if not isinstance(name, str) or not name:
        raise ConfigError("provider name must be a non-empty string")
    timeout = cfg.get("timeout")
    if timeout is not None and (
        isinstance(timeout, bool) or not isinstance(timeout, int | float) or timeout <= 0
    ):
        raise ConfigError("timeout must be a positive number")

    if ptype == "mock":
        return _create_mock(cfg, name)
    kwargs: dict[str, Any] = {
        "name": name,
        "default_model": cfg.get("model"),
        "transport": transport,
    }
    if "api_key_env" in cfg:
        kwargs["api_key_env"] = cfg["api_key_env"]
    if timeout is not None:
        kwargs["timeout"] = float(timeout)
    cls = _HTTP_CLASSES[ptype]
    if ptype == "openai_compatible":
        if "base_url" not in cfg:
            raise ConfigError("openai_compatible provider requires base_url")
        return cls(cfg["base_url"], **kwargs)
    if "base_url" in cfg:
        return cls(cfg["base_url"], **kwargs)
    return cls(**kwargs)


def _create_mock(cfg: Mapping[str, Any], name: str) -> Provider:
    kwargs: dict[str, Any] = {"name": name}
    for key in ("behavior", "script", "chunk_size", "model"):
        if key in cfg:
            kwargs[key] = cfg[key]
    script = kwargs.get("script")
    if script is not None and not isinstance(script, list):
        raise ConfigError("script must be a list of strings")
    chunk = kwargs.get("chunk_size")
    if chunk is not None and (isinstance(chunk, bool) or not isinstance(chunk, int)):
        raise ConfigError("chunk_size must be an integer")
    return MockProvider(**kwargs)


def provider_statuses() -> list[tuple[str, ProviderStatus]]:
    """Status of every provider type with default settings (no network, no secrets)."""
    result: list[tuple[str, ProviderStatus]] = []
    for ptype in available_provider_types():
        if ptype == "openai_compatible":
            result.append(
                (ptype, ProviderStatus(configured=False, detail="requires base_url in config"))
            )
        else:
            result.append((ptype, create_provider(ptype).status()))
    return result
