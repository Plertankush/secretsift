"""Test doubles shared by the provider tests."""

from __future__ import annotations

import contextlib
from collections.abc import Iterable, Iterator, Mapping
from typing import Any


class FakeTransport:
    """Records every call and replays canned responses; never touches the network."""

    def __init__(
        self,
        json_response: dict[str, Any] | None = None,
        events: Iterable[str] = (),
        error: Exception | None = None,
    ) -> None:
        self.json_response = json_response or {}
        self.events = list(events)
        self.error = error
        self.calls: list[tuple[str, str, dict[str, str], dict[str, Any]]] = []

    def _record(self, kind: str, url: str, headers: Mapping[str, str], body: Mapping[str, Any]):
        self.calls.append((kind, url, dict(headers), dict(body)))
        if self.error is not None:
            raise self.error

    def post_json(
        self, url: str, headers: Mapping[str, str], body: Mapping[str, Any]
    ) -> dict[str, Any]:
        self._record("json", url, headers, body)
        return self.json_response

    def stream_sse(
        self, url: str, headers: Mapping[str, str], body: Mapping[str, Any]
    ) -> Iterator[str]:
        self._record("sse", url, headers, body)
        return iter(self.events)

    def stream_ndjson(
        self, url: str, headers: Mapping[str, str], body: Mapping[str, Any]
    ) -> Iterator[str]:
        self._record("ndjson", url, headers, body)
        return iter(self.events)


class FakeInstrumentation:
    """Stands in for ``Instrumentation``: logs provider_traffic enter/exit into ``log``."""

    def __init__(self, log: list[str]) -> None:
        self.log = log

    @contextlib.contextmanager
    def provider_traffic(self, provider_name: str) -> Iterator[None]:
        self.log.append(f"enter:{provider_name}")
        try:
            yield
        finally:
            self.log.append(f"exit:{provider_name}")
