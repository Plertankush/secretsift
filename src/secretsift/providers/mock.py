"""Deterministic offline provider for rehearsing leaks without any network.

Behaviors: ``safe`` (fixed reply that ignores the prompt), ``echo`` (repeats the last user
message, demonstrating output leakage), ``leaky_error`` (raises a ``ProviderError`` containing
the rendered prompt, demonstrating error leakage) and ``scripted`` (cycles through ``script``).
Streaming splits the reply into ``chunk_size`` character chunks so cross-chunk leaks are testable.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from typing import Literal

from secretsift.exceptions import ConfigError, ProviderError
from secretsift.providers.base import (
    Provider,
    ProviderRequest,
    ProviderResponse,
    ProviderStatus,
    render_prompt,
)

MockBehavior = Literal["safe", "echo", "leaky_error", "scripted"]
_BEHAVIORS = ("safe", "echo", "leaky_error", "scripted")
SAFE_REPLY = "I can help with that request."


class MockProvider(Provider):
    """Offline provider; ``requires_network`` is always False."""

    requires_network = False

    def __init__(
        self,
        behavior: MockBehavior = "safe",
        script: list[str] | None = None,
        chunk_size: int = 5,
        *,
        name: str = "mock",
        model: str = "mock-model",
    ) -> None:
        if behavior not in _BEHAVIORS:
            raise ConfigError(f"unknown mock behavior; expected one of {', '.join(_BEHAVIORS)}")
        if chunk_size < 1:
            raise ConfigError("chunk_size must be >= 1")
        if behavior == "scripted" and not script:
            raise ConfigError("scripted behavior needs a non-empty script")
        if script is not None and not all(isinstance(s, str) for s in script):
            raise ConfigError("script entries must be strings")
        self.name = name
        self._behavior = behavior
        self._script = list(script or [])
        self._chunk_size = chunk_size
        self._model = model
        self._calls = 0
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return f"MockProvider(name={self.name!r}, behavior={self._behavior!r})"

    def _reply(self, req: ProviderRequest) -> str:
        if self._behavior == "leaky_error":
            raise ProviderError("mock provider failed while processing: " + render_prompt(req))
        if self._behavior == "echo":
            user = [m.content for m in req.messages if m.role == "user"]
            return user[-1] if user else ""
        if self._behavior == "scripted":
            with self._lock:
                text = self._script[self._calls % len(self._script)]
                self._calls += 1
            return text
        return SAFE_REPLY

    def complete(self, req: ProviderRequest) -> ProviderResponse:
        text = self._reply(req)
        return ProviderResponse(
            text=text, model=req.model or self._model, metadata={"behavior": self._behavior}
        )

    def stream(self, req: ProviderRequest) -> Iterator[str]:
        text = self._reply(req)  # raises eagerly for leaky_error
        size = self._chunk_size
        return iter([text[i : i + size] for i in range(0, len(text), size)])

    def status(self) -> ProviderStatus:
        return ProviderStatus(
            configured=True, detail=f"offline mock provider (behavior={self._behavior})"
        )
