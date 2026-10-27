"""Provider wrapper that records every request, output and error as secretsift events.

Event order for ``complete``: ``ai_request``, ``ai_output`` (or ``error_report``). For ``stream``:
``ai_request``, one ``ai_output`` per chunk (``metadata["chunk_index"]``), then one aggregated
``ai_output`` (``metadata["aggregated"] = True``) holding the whole text, so a secret split across
chunks is still seen whole. Errors are emitted as ``error_report`` events (credential-redacted
only; synthetic values are deliberately kept so leaks through errors are detected) and re-raised.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

from secretsift.core.events import EventCollector
from secretsift.models import Destination
from secretsift.providers.base import (
    Provider,
    ProviderRequest,
    ProviderResponse,
    ProviderStatus,
    render_prompt,
)
from secretsift.providers.transport import redact_credentials_text

if TYPE_CHECKING:
    from secretsift.instrumentation import Instrumentation


class InstrumentedProvider(Provider):
    """Wraps a :class:`Provider`, mirroring its interface."""

    def __init__(
        self,
        inner: Provider,
        collector: EventCollector,
        instrumentation: Instrumentation | None = None,
        component: str | None = None,
    ) -> None:
        self._inner = inner
        self._collector = collector
        self._instrumentation = instrumentation
        self._component = component or f"provider.{inner.name}"
        self.name = inner.name
        self.requires_network = inner.requires_network

    def __repr__(self) -> str:
        return f"InstrumentedProvider({self._inner!r})"

    def status(self) -> ProviderStatus:
        return self._inner.status()

    def credential_env_names(self) -> tuple[str, ...]:
        return self._inner.credential_env_names()

    def _traffic(self) -> contextlib.AbstractContextManager[Any]:
        if self._instrumentation is None:
            return contextlib.nullcontext()
        return self._instrumentation.provider_traffic(self._inner.name)

    def _meta(self, req: ProviderRequest, **extra: Any) -> dict[str, Any]:
        meta: dict[str, Any] = {"provider": self._inner.name, "model": req.model or ""}
        meta.update(extra)
        return meta

    def _emit_request(self, req: ProviderRequest) -> None:
        self._collector.record(
            Destination.AI_REQUEST,
            self._component,
            render_prompt(req, include_params=True),
            metadata=self._meta(req),
        )

    def _emit_error(self, req: ProviderRequest, exc: BaseException) -> None:
        message = redact_credentials_text(f"{type(exc).__name__}: {exc}")
        self._collector.record(
            Destination.ERROR_REPORT,
            self._component,
            message,
            metadata=self._meta(req, source="provider"),
        )

    def complete(self, req: ProviderRequest) -> ProviderResponse:
        self._emit_request(req)
        try:
            with self._traffic():
                resp = self._inner.complete(req)
        except Exception as exc:
            self._emit_error(req, exc)
            raise
        self._collector.record(
            Destination.AI_OUTPUT,
            self._component,
            resp.text,
            metadata=self._meta(req, model=resp.model or req.model or ""),
        )
        return resp

    def stream(self, req: ProviderRequest) -> Iterator[str]:
        self._emit_request(req)
        chunks: list[str] = []
        done = False
        try:
            with self._traffic():
                inner = iter(self._inner.stream(req))
            while True:
                with self._traffic():
                    chunk = next(inner, None)
                if chunk is None:
                    done = True
                    break
                if not chunk:
                    continue
                self._collector.record(
                    Destination.AI_OUTPUT,
                    self._component,
                    chunk,
                    metadata=self._meta(req, chunk_index=len(chunks)),
                )
                chunks.append(chunk)
                yield chunk
        except Exception as exc:
            self._emit_error(req, exc)
            raise
        finally:
            if chunks or done:
                self._collector.record(
                    Destination.AI_OUTPUT,
                    self._component,
                    "".join(chunks),
                    metadata=self._meta(
                        req, aggregated=True, chunk_count=len(chunks), complete=done
                    ),
                )
