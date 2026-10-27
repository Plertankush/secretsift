"""Provider data models, the abstract :class:`Provider` and a shared HTTP adapter base.

Prompt and output text can carry synthetic secrets, so those fields are excluded from ``repr``
and ``model_dump``. API keys are never stored: adapters keep only the *name* of an environment
variable and read the value at call time.
"""

from __future__ import annotations

import abc
import json
import os
import re
from collections.abc import Iterator, Mapping
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from secretsift.exceptions import ConfigError, ProviderError
from secretsift.providers.transport import (
    Transport,
    UrllibTransport,
    is_loopback_host,
    validate_base_url,
)

_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class Message(BaseModel):
    """One chat message. ``content`` is never repr'd or dumped."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    role: Literal["system", "user", "assistant"]
    content: str = Field(repr=False, exclude=True)


class ProviderRequest(BaseModel):
    """A provider-neutral chat request."""

    model_config = ConfigDict(extra="forbid")

    messages: list[Message] = Field(default_factory=list, repr=False, exclude=True)
    model: str | None = None
    system: str | None = Field(default=None, repr=False, exclude=True)
    params: dict[str, Any] = Field(default_factory=dict, repr=False, exclude=True)


class ProviderResponse(BaseModel):
    """A provider-neutral completion. ``text`` is never repr'd or dumped."""

    model_config = ConfigDict(extra="forbid")

    text: str = Field(repr=False, exclude=True)
    model: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProviderStatus(BaseModel):
    """Whether a provider can be used; ``detail`` never contains credential values."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    configured: bool
    detail: str


def render_prompt(req: ProviderRequest, *, include_params: bool = False) -> str:
    """Render ``system`` and each message as ``role: content`` lines (optionally + params)."""
    lines: list[str] = []
    if req.system:
        lines.append(f"system: {req.system}")
    lines.extend(f"{m.role}: {m.content}" for m in req.messages)
    if include_params and req.params:
        lines.append("params: " + json.dumps(req.params, sort_keys=True, default=str))
    return "\n".join(lines)


def merged_system(req: ProviderRequest) -> str | None:
    """``req.system`` plus any system-role messages, joined; None when there are none."""
    parts = [req.system] if req.system else []
    parts.extend(m.content for m in req.messages if m.role == "system")
    return "\n\n".join(parts) if parts else None


class Provider(abc.ABC):
    """An AI provider. Real adapters set ``requires_network = True``."""

    name: str
    requires_network: bool

    @abc.abstractmethod
    def complete(self, req: ProviderRequest) -> ProviderResponse:
        """Return the full completion."""

    @abc.abstractmethod
    def stream(self, req: ProviderRequest) -> Iterator[str]:
        """Yield the completion as text chunks."""

    @abc.abstractmethod
    def status(self) -> ProviderStatus:
        """Report configuration state without contacting the network."""

    def credential_env_names(self) -> tuple[str, ...]:
        """Names of environment variables holding this provider's credentials."""
        return ()

    def __repr__(self) -> str:
        return f"{type(self).__name__}(name={self.name!r})"


def validate_env_name(value: object, what: str = "api_key_env") -> str:
    """Accept only a plausible environment variable name (never a pasted secret)."""
    if not isinstance(value, str) or not _ENV_NAME.match(value):
        raise ConfigError(f"{what} must be an environment variable name")
    return value


class HttpProvider(Provider):
    """Shared plumbing for adapters that talk HTTP through a :class:`Transport`."""

    #: When False the request may omit the model (e.g. llama.cpp serves one model).
    model_required = True

    def __init__(
        self,
        *,
        name: str,
        base_url: str,
        api_key_env: str | None = None,
        default_model: str | None = None,
        transport: Transport | None = None,
        timeout: float = 60.0,
    ) -> None:
        self.name = name
        self._base_url = validate_base_url(base_url)
        self._api_key_env = validate_env_name(api_key_env) if api_key_env is not None else None
        self._default_model = default_model
        self._transport: Transport = transport or UrllibTransport(timeout=timeout)
        self.requires_network = not is_loopback_host(urlsplit(self._base_url).hostname)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(name={self.name!r}, base_url={self._base_url!r})"

    def credential_env_names(self) -> tuple[str, ...]:
        return (self._api_key_env,) if self._api_key_env else ()

    def _api_key(self) -> str | None:
        """Read the key from the environment now; None when this provider needs no key."""
        if self._api_key_env is None:
            return None
        value = os.environ.get(self._api_key_env, "").strip()
        if not value:
            raise ProviderError(f"environment variable {self._api_key_env} is not set")
        return value

    def _model(self, req: ProviderRequest) -> str | None:
        model = req.model or self._default_model
        if not model and self.model_required:
            raise ProviderError(f"{self.name}: no model given in the request or provider config")
        return model

    def status(self) -> ProviderStatus:
        target = f"endpoint {self._base_url}"
        if self._api_key_env is None:
            return ProviderStatus(configured=True, detail=f"no credentials required; {target}")
        if os.environ.get(self._api_key_env, "").strip():
            return ProviderStatus(configured=True, detail=f"{self._api_key_env} is set; {target}")
        return ProviderStatus(configured=False, detail=f"{self._api_key_env} is not set")


def object_list(data: Mapping[str, Any], key: str) -> list[dict[str, Any]]:
    """Return ``data[key]`` as a list of dicts, ignoring anything else."""
    value = data.get(key)
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]
