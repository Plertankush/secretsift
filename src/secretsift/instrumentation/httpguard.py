"""``http.client`` guard: emits url/headers/body events and enforces the network policy.

Covers urllib, requests/urllib3 and anything else built on ``http.client.HTTPConnection``.
Host checks run in ``putrequest``, before any DNS lookup, connect or byte is sent.
"""

from __future__ import annotations

import http.client
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, Any

from secretsift.exceptions import OfflineViolationError
from secretsift.instrumentation.sockets import patch_attr
from secretsift.models import Destination

if TYPE_CHECKING:
    from secretsift.instrumentation.capture import Instrumentation

REDACTED = "[HEADER-REDACTED]"
SENSITIVE_HEADERS = frozenset(
    {"authorization", "x-api-key", "x-goog-api-key", "cookie", "proxy-authorization"}
)
_HEADERS = "_secretsift_headers"
_PHASE = "_secretsift_phase"
_DEPTH = "_secretsift_depth"


def _text(value: Any) -> str:
    return value.decode("latin-1") if isinstance(value, bytes | bytearray) else str(value)


def safe_header_value(name: str, value: str) -> str:
    """Return ``value`` unless the header carries credentials."""
    return REDACTED if name.strip().casefold() in SENSITIVE_HEADERS else value


def format_headers(items: Iterable[tuple[str, str]]) -> str:
    """Render already-sanitized ``(name, value)`` pairs as header lines."""
    return "\n".join(f"{name}: {value}" for name, value in items)


def _full_url(conn: http.client.HTTPConnection, url: str) -> str:
    if url.startswith(("http://", "https://")) or url == "*":
        return url
    https = getattr(http.client, "HTTPSConnection", None)
    scheme = "https" if https is not None and isinstance(conn, https) else "http"
    host = f"[{conn.host}]" if ":" in conn.host else conn.host
    port = "" if conn.port == conn.default_port else f":{conn.port}"
    return f"{scheme}://{host}{port}{url}"


def install(active: Callable[[], Instrumentation | None]) -> Callable[[], None]:
    """Patch ``HTTPConnection.putrequest/putheader/endheaders/send``."""
    cls = http.client.HTTPConnection
    orig_putrequest = cls.putrequest
    orig_putheader = cls.putheader
    orig_endheaders = cls.endheaders
    orig_send = cls.send

    def putrequest(self: Any, method: str, url: str, *args: Any, **kwargs: Any) -> Any:
        inst = active()
        if inst is None:
            return orig_putrequest(self, method, url, *args, **kwargs)
        setattr(self, _HEADERS, [])
        setattr(self, _PHASE, None)
        meta: dict[str, Any] = {"part": "url", "method": method}
        component = f"{inst.component_prefix}.http"
        try:
            inst.guard_host(self.host)
        except OfflineViolationError:
            meta["blocked"] = True
            inst.record(Destination.HTTP_REQUEST, component, _full_url(self, url), metadata=meta)
            raise
        inst.record(Destination.HTTP_REQUEST, component, _full_url(self, url), metadata=meta)
        return orig_putrequest(self, method, url, *args, **kwargs)

    def putheader(self: Any, header: Any, *values: Any) -> Any:
        headers = getattr(self, _HEADERS, None)
        if headers is None:
            headers = []
            setattr(self, _HEADERS, headers)
        name = _text(header)
        headers.append((name, safe_header_value(name, "\r\n\t".join(_text(v) for v in values))))
        return orig_putheader(self, header, *values)

    def endheaders(self: Any, message_body: Any = None, **kwargs: Any) -> Any:
        inst = active()
        if inst is not None:
            inst.record(
                Destination.HTTP_REQUEST,
                f"{inst.component_prefix}.http",
                format_headers(getattr(self, _HEADERS, [])),
                metadata={"part": "headers"},
            )
            setattr(self, _PHASE, "headers")
        return orig_endheaders(self, message_body, **kwargs)

    def send(self: Any, data: Any) -> Any:
        inst = active()
        phase = getattr(self, _PHASE, None)
        if inst is None or phase is None:
            return orig_send(self, data)
        depth = getattr(self, _DEPTH, 0)
        setattr(self, _DEPTH, depth + 1)
        try:
            if depth == 0:
                if phase == "headers":
                    setattr(self, _PHASE, "body")  # the first send is the header block
                elif isinstance(data, bytes | bytearray | memoryview) and len(data):
                    provider = inst.current_provider()
                    meta: dict[str, Any] = {"part": "body", "bytes": len(data)}
                    if provider is not None:
                        meta["provider"] = provider
                    inst.record(
                        Destination.HTTP_REQUEST,
                        f"{inst.component_prefix}.http",
                        bytes(data).decode("utf-8", "replace"),
                        metadata=meta,
                        approved=provider is not None,
                    )
            return orig_send(self, data)
        finally:
            setattr(self, _DEPTH, depth)

    restores = [
        patch_attr(cls, "putrequest", putrequest),
        patch_attr(cls, "putheader", putheader),
        patch_attr(cls, "endheaders", endheaders),
        patch_attr(cls, "send", send),
    ]

    def restore() -> None:
        for undo in reversed(restores):
            undo()

    return restore
