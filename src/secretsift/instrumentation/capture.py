"""The :class:`Instrumentation` context manager and its process-global patch bookkeeping."""

from __future__ import annotations

import contextlib
import threading
from collections.abc import Iterator, Sequence
from pathlib import Path
from types import TracebackType
from typing import Any

from secretsift.core.events import EventCollector
from secretsift.exceptions import OfflineViolationError
from secretsift.instrumentation import httpguard, logcapture, sockets, stdio
from secretsift.instrumentation.storage import scan_paths
from secretsift.models import Destination

_LOCK = threading.RLock()
_STACK: list[Instrumentation] = []
_GLOBAL = contextlib.ExitStack()


def _active() -> Instrumentation | None:
    try:
        return _STACK[-1]
    except IndexError:
        return None


class Instrumentation:
    """Records where data surfaces and enforces the network policy while active.

    Patches are process-global and reference counted: nested or re-entrant use installs them
    once, events go to the innermost active instance, and everything is restored on exit.
    """

    def __init__(
        self,
        collector: EventCollector,
        *,
        offline: bool,
        network_allowlist: Sequence[str] = (),
        storage_paths: Sequence[Path] = (),
        capture_stdio: bool = True,
        component_prefix: str = "app",
    ) -> None:
        self.collector = collector
        self.offline = offline
        self.capture_stdio = capture_stdio
        self.component_prefix = component_prefix
        self._allowlist = sockets.normalize_allowlist(network_allowlist)
        self._storage_paths = tuple(Path(p) for p in storage_paths)
        self._tls = threading.local()

    def __enter__(self) -> Instrumentation:
        with _LOCK:
            if not _STACK:
                try:
                    _GLOBAL.callback(logcapture.install(_active))
                    _GLOBAL.callback(httpguard.install(_active))
                    _GLOBAL.callback(sockets.install(_active))
                    _GLOBAL.callback(stdio.install(_active))
                except BaseException:
                    _GLOBAL.close()
                    raise
            _STACK.append(self)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        with _LOCK:
            if len(_STACK) == 1 and _STACK[0] is self:
                try:
                    _GLOBAL.close()  # restores patches; tees drain while still active
                finally:
                    _STACK.clear()
                return
            for index in range(len(_STACK) - 1, -1, -1):
                if _STACK[index] is self:
                    del _STACK[index]
                    break

    def record(
        self,
        destination: Destination,
        component: str,
        payload: str,
        *,
        metadata: dict[str, Any] | None = None,
        location: str | None = None,
        approved: bool = False,
    ) -> None:
        """Emit one event to the collector."""
        self.collector.record(
            destination,
            component,
            payload,
            metadata=metadata,
            location=location,
            approved=approved,
        )

    def guard_host(self, host: str | bytes) -> None:
        """Raise :class:`OfflineViolationError` when ``host`` may not be contacted."""
        if self.offline or self._allowlist:
            if not sockets.host_allowed(host, offline=self.offline, allowlist=self._allowlist):
                raise OfflineViolationError(sockets.blocked_message(host, offline=self.offline))

    @contextlib.contextmanager
    def provider_traffic(self, provider_name: str) -> Iterator[None]:
        """Mark HTTP bodies sent by this thread as approved provider traffic."""
        stack: list[str] = self._tls.__dict__.setdefault("providers", [])
        stack.append(provider_name)
        try:
            yield
        finally:
            stack.pop()

    def current_provider(self) -> str | None:
        """Innermost provider name active on the calling thread."""
        stack: list[str] = self._tls.__dict__.get("providers", [])
        return stack[-1] if stack else None

    def snapshot_storage(self) -> None:
        """Emit ``storage`` events for the explicit storage paths."""
        scan_paths(self._storage_paths, self.collector)
