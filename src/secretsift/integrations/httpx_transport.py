"""httpx transport wrapper that observes and polices outbound requests.

``httpx`` is an optional dependency: importing this module works without it, constructing
:class:`SecretsiftTransport` does not. Events have the same shape as the ``http.client`` guard.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from secretsift.core.events import EventCollector
from secretsift.exceptions import OfflineViolationError, SecretsiftError
from secretsift.instrumentation.httpguard import format_headers, safe_header_value
from secretsift.instrumentation.sockets import blocked_message, host_allowed, normalize_allowlist
from secretsift.models import Destination

try:
    import httpx as _httpx
except ImportError:  # pragma: no cover - exercised only where httpx is absent
    _httpx = None  # type: ignore[assignment]


class _MissingSync:
    """Stand-in base when httpx is not installed."""


class _MissingAsync:
    """Stand-in base when httpx is not installed."""


_SyncBase: Any = _httpx.BaseTransport if _httpx is not None else _MissingSync
_AsyncBase: Any = _httpx.AsyncBaseTransport if _httpx is not None else _MissingAsync

COMPONENT = "httpx"


def sanitized_header_text(items: Iterable[tuple[str, str]]) -> str:
    """Header lines with credential-bearing values replaced before any event is created."""
    return format_headers((name, safe_header_value(name, value)) for name, value in items)


def decode_body(body: bytes) -> str:
    """Decode a request body for inspection (undecodable bytes are replaced)."""
    return body.decode("utf-8", "replace")


class SecretsiftTransport(_SyncBase, _AsyncBase):  # type: ignore[misc]
    """Wraps an ``httpx`` transport (sync or async) and emits ``http_request`` events.

    Per request: a ``url`` event, a ``headers`` event (credential headers redacted) and, when a
    body exists, a ``body`` event that is approved only if ``provider_name`` is set. Requests to
    hosts the network policy forbids raise :class:`OfflineViolationError` before anything is sent.
    """

    def __init__(
        self,
        wrapped: Any,
        collector: EventCollector,
        *,
        offline: bool,
        allowlist: Iterable[str] = (),
        provider_name: str | None = None,
    ) -> None:
        if _httpx is None:
            raise SecretsiftError("SecretsiftTransport requires the optional dependency 'httpx'")
        self._wrapped = wrapped
        self._collector = collector
        self._offline = offline
        self._allowlist = normalize_allowlist(allowlist)
        self._provider = provider_name

    def _observe(self, request: Any, body: bytes) -> None:
        """Enforce the host policy, then emit url, headers and body events."""
        record = self._collector.record
        url_meta: dict[str, Any] = {"part": "url", "method": request.method}
        host = request.url.host
        if (self._offline or self._allowlist) and not host_allowed(
            host, offline=self._offline, allowlist=self._allowlist
        ):
            url_meta["blocked"] = True
            record(Destination.HTTP_REQUEST, COMPONENT, str(request.url), metadata=url_meta)
            raise OfflineViolationError(blocked_message(host, offline=self._offline))
        record(Destination.HTTP_REQUEST, COMPONENT, str(request.url), metadata=url_meta)
        record(
            Destination.HTTP_REQUEST,
            COMPONENT,
            sanitized_header_text(request.headers.multi_items()),
            metadata={"part": "headers"},
        )
        if body:
            meta: dict[str, Any] = {"part": "body", "bytes": len(body)}
            if self._provider is not None:
                meta["provider"] = self._provider
            record(
                Destination.HTTP_REQUEST,
                COMPONENT,
                decode_body(body),
                metadata=meta,
                approved=self._provider is not None,
            )

    def handle_request(self, request: Any) -> Any:
        self._observe(request, bytes(request.read()))
        return self._wrapped.handle_request(request)

    async def handle_async_request(self, request: Any) -> Any:
        self._observe(request, bytes(await request.aread()))
        return await self._wrapped.handle_async_request(request)

    def close(self) -> None:
        close = getattr(self._wrapped, "close", None)
        if close is not None:
            close()

    async def aclose(self) -> None:
        aclose = getattr(self._wrapped, "aclose", None)
        if aclose is not None:
            await aclose()
