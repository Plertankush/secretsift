"""Abstract interfaces between modules. Implementations live in their own packages.

Dependency direction (no cycles): models/exceptions/contracts <- everything else.
"""

from __future__ import annotations

import abc
from collections.abc import Iterator, Sequence
from typing import Protocol, runtime_checkable

from secretsift.models import (
    Decision,
    Destination,
    Event,
    Match,
    Report,
    SyntheticValue,
)


@runtime_checkable
class SecretRegistryProtocol(Protocol):
    """Tracks active synthetic values and finds them (with variants) in text."""

    def register(self, value: SyntheticValue) -> None: ...
    def get(self, value_id: str) -> SyntheticValue: ...
    def values(self) -> Sequence[SyntheticValue]: ...
    def find(self, text: str) -> list[Match]: ...
    def redact(self, text: str) -> str:
        """Replace every match with ``[REDACTED:<value_id>]``. Idempotent."""
        ...

    def clear(self) -> None:
        """Drop all values (cleanup lifecycle)."""
        ...


class Inspector(abc.ABC):
    """Examines events for one or more destinations and reports matches."""

    name: str
    destinations: frozenset[Destination]

    @abc.abstractmethod
    def inspect(self, event: Event, registry: SecretRegistryProtocol) -> list[Match]: ...


class PolicyEvaluatorProtocol(Protocol):
    def decide(self, scenario: str, value: SyntheticValue, event: Event) -> Decision: ...


class Reporter(abc.ABC):
    """Renders a :class:`Report` to a string. Must escape all untrusted text."""

    format_name: str

    @abc.abstractmethod
    def render(self, report: Report) -> str: ...


@runtime_checkable
class EventSink(Protocol):
    """Anything instrumentation can push events into."""

    def emit(self, event: Event) -> None: ...


class EventSource(Protocol):
    def __iter__(self) -> Iterator[Event]: ...
