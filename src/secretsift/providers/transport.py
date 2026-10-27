"""HTTP transport used by every network provider adapter.

All provider network traffic goes through the :class:`Transport` protocol so tests can inject a
fake. :class:`UrllibTransport` is the stdlib implementation (``http.client``): bounded timeouts,
bounded response/stream/line sizes, no cross-host redirects, JSON helpers, and SSE / NDJSON
line parsing. Proxy environment variables are not consulted.

Error messages carry the status code, the host and a sanitized, credential-redacted and truncated
server error text. They never contain request bodies, header values or URLs with query strings.
"""

from __future__ import annotations

import contextlib
import http.client
import ipaddress
import json
import re
import ssl
import time
from collections.abc import Iterable, Iterator, Mapping
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urljoin, urlsplit

from secretsift.exceptions import ConfigError, ProviderError
from secretsift.version import __version__

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_CREDENTIAL_HEADERS = frozenset({"authorization", "x-api-key", "x-goog-api-key"})
_DEFAULT_PORTS = {"http": 80, "https": 443}
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]+")

_FALLBACK_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"(?i)\b(authorization|x-api-key|x-goog-api-key|api[_-]?key|access[_-]?token"
            r"|token|secret|password)\b(\s*[\"']?\s*[:=]\s*[\"']?)(?:Bearer\s+)?[^\s\"',;&]+"
        ),
        r"\1\2[REDACTED]",
    ),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{6,}"), "Bearer [REDACTED]"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{8,}"), "[REDACTED]"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{20,}"), "[REDACTED]"),
)


def _fallback_redact(text: str) -> str:
    """Private credential masker used until the shared evidence redactor is importable."""
    for pattern, repl in _FALLBACK_PATTERNS:
        text = pattern.sub(repl, text)
    return text


def redact_credentials_text(text: str) -> str:
    """Mask credential-looking substrings (shared redactor when available, else fallback)."""
    try:
        from secretsift.evidence.redaction import redact_credentials
    except ImportError:
        return _fallback_redact(text)
    return redact_credentials(text)


def sanitize_text(text: str, limit: int = 500) -> str:
    """Credential-redact, make printable and truncate untrusted text for error messages."""
    cleaned = _CONTROL_CHARS.sub(" ", redact_credentials_text(text)).strip()
    if len(cleaned) > limit:
        cleaned = cleaned[:limit] + "..."
    return cleaned


class ProviderHTTPError(ProviderError):
    """Non-success HTTP status. Carries the status code; message is already sanitized."""

    def __init__(self, message: str, status_code: int) -> None:
        super().__init__(message)
        self.status_code = status_code


def is_loopback_host(host: str | None) -> bool:
    """True for localhost and loopback IP literals (127.0.0.0/8, ::1)."""
    if not host:
        return False
    host = host.lower().strip("[]")
    if host in _LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_base_url(url: object) -> str:
    """Return ``url`` without trailing slash; reject non-http(s), missing host or userinfo."""
    if not isinstance(url, str) or not url.strip():
        raise ConfigError("base_url must be a non-empty string")
    url = url.strip()
    try:
        parts = urlsplit(url)
        host = parts.hostname
        parts.port  # noqa: B018 - raises ValueError for an invalid port
    except ValueError:
        raise ConfigError("base_url is not a valid URL") from None
    if parts.scheme not in ("http", "https") or not host:
        raise ConfigError("base_url must be an http(s) URL with a host")
    if parts.username is not None or parts.password is not None:
        raise ConfigError("base_url must not contain credentials; use api_key_env instead")
    if parts.query or parts.fragment:
        raise ConfigError("base_url must not contain a query string or fragment")
    return url.rstrip("/")


def parse_json_object(text: str, what: str = "response") -> dict[str, Any]:
    """Parse ``text`` as a JSON object; the error never echoes the content."""
    try:
        data = json.loads(text)
    except ValueError:
        raise ProviderError(f"{what} was not valid JSON") from None
    if not isinstance(data, dict):
        raise ProviderError(f"{what} was not a JSON object")
    return data


def error_text_from_json(data: object) -> str | None:
    """Extract the human message from common provider error shapes, if present."""
    if isinstance(data, dict):
        err = data.get("error", data)
        if isinstance(err, dict):
            msg = err.get("message")
            return msg if isinstance(msg, str) else None
        if isinstance(err, str):
            return err
        msg = data.get("message")
        return msg if isinstance(msg, str) else None
    return None


def http_error(status: int, host: str, body_text: str) -> ProviderHTTPError:
    """Build the sanitized error for a non-success status (no request data involved)."""
    text = body_text
    try:
        extracted = error_text_from_json(json.loads(body_text))
    except ValueError:
        extracted = None
    if extracted:
        text = extracted
    detail = sanitize_text(text)
    msg = f"HTTP {status} from {host}" + (f": {detail}" if detail else "")
    return ProviderHTTPError(msg, status)


def iter_sse_data(lines: Iterable[bytes]) -> Iterator[str]:
    """Yield the ``data`` payload of each server-sent event from raw lines.

    Handles ``data:`` with or without a space, multi-line data, comments, CRLF, a leading BOM
    and a final event without a trailing blank line. Each line is decoded whole so multi-byte
    characters are never split.
    """
    parts: list[str] = []
    first = True
    for raw in lines:
        line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
        if first:
            line = line.lstrip("﻿")
            first = False
        if not line:
            if parts:
                yield "\n".join(parts)
                parts = []
            continue
        if line.startswith(":"):
            continue
        field, sep, value = line.partition(":")
        if sep and value.startswith(" "):
            value = value[1:]
        if field == "data":
            parts.append(value)
    if parts:
        yield "\n".join(parts)


def iter_ndjson_lines(lines: Iterable[bytes]) -> Iterator[str]:
    """Yield each non-empty line of a newline-delimited stream as text."""
    for raw in lines:
        text = raw.decode("utf-8", errors="replace").strip()
        if text:
            yield text


@runtime_checkable
class Transport(Protocol):
    """Minimal HTTP surface the adapters need. Streams are lazy iterators."""

    def post_json(
        self, url: str, headers: Mapping[str, str], body: Mapping[str, Any]
    ) -> dict[str, Any]:
        """POST a JSON body and return the parsed JSON object response."""
        ...

    def stream_sse(
        self, url: str, headers: Mapping[str, str], body: Mapping[str, Any]
    ) -> Iterator[str]:
        """POST a JSON body and yield each server-sent event's data payload."""
        ...

    def stream_ndjson(
        self, url: str, headers: Mapping[str, str], body: Mapping[str, Any]
    ) -> Iterator[str]:
        """POST a JSON body and yield each non-empty NDJSON line."""
        ...


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    scheme = parts.scheme
    return scheme, (parts.hostname or "").lower(), parts.port or _DEFAULT_PORTS.get(scheme, 0)


@contextlib.contextmanager
def _mapped(host: str) -> Iterator[None]:
    """Translate low-level network failures into credential-free ProviderErrors."""
    try:
        yield
    except ProviderError:
        raise
    except TimeoutError:
        raise ProviderError(f"request to {host} timed out") from None
    except ssl.SSLError:
        raise ProviderError(f"TLS error talking to {host}") from None
    except http.client.IncompleteRead:
        raise ProviderError(f"response from {host} was interrupted") from None
    except http.client.HTTPException:
        raise ProviderError(f"invalid HTTP response from {host}") from None
    except OSError as exc:
        raise ProviderError(
            f"connection to {host} failed ({type(exc).__name__}): {sanitize_text(str(exc), 120)}"
        ) from None
    except ValueError:
        raise ProviderError(f"invalid request for {host}") from None


class UrllibTransport:
    """Stdlib ``http.client`` transport with hard resource limits.

    Redirects: only 307/308 to the same scheme, host and port are followed (method and body are
    preserved); everything else is refused. Credential headers are never sent over plain http to
    a non-loopback host.
    """

    def __init__(
        self,
        *,
        timeout: float = 60.0,
        total_timeout: float = 300.0,
        max_response_bytes: int = 8_000_000,
        max_stream_bytes: int = 32_000_000,
        max_line_bytes: int = 1_000_000,
        max_redirects: int = 3,
        max_error_bytes: int = 4_096,
    ) -> None:
        if timeout <= 0 or total_timeout <= 0:
            raise ConfigError("timeouts must be positive")
        self._timeout = timeout
        self._total_timeout = total_timeout
        self._max_response = max_response_bytes
        self._max_stream = max_stream_bytes
        self._max_line = max_line_bytes
        self._max_redirects = max_redirects
        self._max_error = max_error_bytes

    def __repr__(self) -> str:
        return f"UrllibTransport(timeout={self._timeout})"

    # -- public API -------------------------------------------------------------------------

    def post_json(
        self, url: str, headers: Mapping[str, str], body: Mapping[str, Any]
    ) -> dict[str, Any]:
        host = self._host(url)
        conn, resp = self._open(url, headers, body, "application/json")
        try:
            with _mapped(host):
                data = resp.read(self._max_response + 1)
        finally:
            conn.close()
        if len(data) > self._max_response:
            raise ProviderError(f"response from {host} exceeds the size limit")
        return parse_json_object(data.decode("utf-8", errors="replace"), f"response from {host}")

    def stream_sse(
        self, url: str, headers: Mapping[str, str], body: Mapping[str, Any]
    ) -> Iterator[str]:
        return iter_sse_data(self._iter_lines(url, headers, body, "text/event-stream"))

    def stream_ndjson(
        self, url: str, headers: Mapping[str, str], body: Mapping[str, Any]
    ) -> Iterator[str]:
        return iter_ndjson_lines(self._iter_lines(url, headers, body, "application/x-ndjson"))

    # -- internals --------------------------------------------------------------------------

    @staticmethod
    def _host(url: str) -> str:
        parts = urlsplit(url)
        host = parts.hostname or "unknown-host"
        return f"{host}:{parts.port}" if parts.port else host

    def _iter_lines(
        self, url: str, headers: Mapping[str, str], body: Mapping[str, Any], accept: str
    ) -> Iterator[bytes]:
        host = self._host(url)
        conn, resp = self._open(url, headers, body, accept)
        try:
            deadline = time.monotonic() + self._total_timeout
            total = 0
            while True:
                with _mapped(host):
                    line = resp.readline(self._max_line + 1)
                if not line:
                    return
                if len(line) > self._max_line:
                    raise ProviderError(f"stream line from {host} exceeds the size limit")
                total += len(line)
                if total > self._max_stream:
                    raise ProviderError(f"stream from {host} exceeds the size limit")
                if time.monotonic() > deadline:
                    raise ProviderError(f"stream from {host} exceeded the total time limit")
                yield line
        finally:
            conn.close()

    def _open(
        self, url: str, headers: Mapping[str, str], body: Mapping[str, Any], accept: str
    ) -> tuple[http.client.HTTPConnection, http.client.HTTPResponse]:
        try:
            payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        except (TypeError, ValueError):
            raise ProviderError("request body is not JSON-serializable") from None
        hdrs = {
            "Content-Type": "application/json",
            "Accept": accept,
            "Accept-Encoding": "identity",
            "User-Agent": f"secretsift/{__version__}",
        }
        hdrs.update(headers)
        origin = _origin(url)
        current = url
        for _ in range(self._max_redirects + 1):
            parts = urlsplit(current)
            host = self._host(current)
            self._check(parts.scheme, parts.hostname, hdrs, host)
            target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
            conn = self._connect(parts.scheme, parts.hostname or "", parts.port)
            try:
                with _mapped(host):
                    conn.request("POST", target, body=payload, headers=hdrs)
                    resp = conn.getresponse()
                status = resp.status
                if status in (307, 308):
                    location = resp.getheader("Location")
                    conn.close()
                    if not location:
                        raise ProviderError(f"redirect from {host} had no Location")
                    current = urljoin(current, location)
                    if _origin(current) != origin:
                        raise ProviderError(f"redirect from {host} to another origin refused")
                    continue
                if 200 <= status < 300:
                    return conn, resp
                if 300 <= status < 400:
                    raise ProviderError(f"HTTP {status} redirect from {host} not followed")
                with _mapped(host):
                    raw = resp.read(self._max_error)
                raise http_error(status, host, raw.decode("utf-8", errors="replace"))
            except BaseException:
                conn.close()
                raise
        raise ProviderError(f"too many redirects from {host}")

    @staticmethod
    def _check(scheme: str, hostname: str | None, hdrs: Mapping[str, str], host: str) -> None:
        if scheme not in ("http", "https") or not hostname:
            raise ProviderError("request URL must be http(s) with a host")
        for key, value in hdrs.items():
            if re.search(r"[\r\n\x00]", key) or re.search(r"[\r\n\x00]", value):
                raise ProviderError(f"invalid header {key!r}: control characters")
        if scheme == "http" and not is_loopback_host(hostname):
            if any(k.lower() in _CREDENTIAL_HEADERS for k in hdrs):
                raise ProviderError(f"refusing to send credentials to {host} over plain http")

    def _connect(self, scheme: str, hostname: str, port: int | None) -> http.client.HTTPConnection:
        if scheme == "https":
            return http.client.HTTPSConnection(
                hostname, port, timeout=self._timeout, context=ssl.create_default_context()
            )
        return http.client.HTTPConnection(hostname, port, timeout=self._timeout)
