"""Thread-safe in-memory event collector used by all instrumentation."""

from __future__ import annotations

import datetime as dt
import threading
import uuid
from collections.abc import Iterator
from typing import Any

from secretsift.models import Destination, Event

_MAX_EVENTS_DEFAULT = 100_000
_MAX_PAYLOAD_DEFAULT = 1_000_000  # characters; larger payloads are truncated, flagged in metadata


class EventCollector:
    """Collects :class:`Event` objects. Implements ``EventSink``."""

    def __init__(
        self,
        max_events: int = _MAX_EVENTS_DEFAULT,
        max_payload_chars: int = _MAX_PAYLOAD_DEFAULT,
    ) -> None:
        self._events: list[Event] = []
        self._lock = threading.Lock()
        self._max_events = max_events
        self._max_payload = max_payload_chars
        self.dropped = 0

    def emit(self, event: Event) -> None:
        with self._lock:
            if len(self._events) >= self._max_events:
                self.dropped += 1
                return
            self._events.append(event)

    def record(
        self,
        destination: Destination,
        component: str,
        payload: str,
        *,
        metadata: dict[str, Any] | None = None,
        location: str | None = None,
        approved: bool = False,
    ) -> Event:
        """Build and emit an event. Truncates oversized payloads (resource limit)."""
        meta = dict(metadata or {})
        if len(payload) > self._max_payload:
            payload = payload[: self._max_payload]
            meta["truncated"] = True
        event = Event(
            id=f"ev_{uuid.uuid4().hex[:10]}",
            destination=destination,
            component=component,
            timestamp=dt.datetime.now(dt.UTC),
            payload=payload,
            metadata=meta,
            location=location,
            approved=approved,
        )
        self.emit(event)
        return event

    def __iter__(self) -> Iterator[Event]:
        with self._lock:
            snapshot = list(self._events)
        return iter(snapshot)

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            self.dropped = 0
