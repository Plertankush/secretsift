"""Shared base class for inspectors that search an event payload with the secret registry."""

from __future__ import annotations

from secretsift.contracts import Inspector, SecretRegistryProtocol
from secretsift.models import Destination, Event, Match


class PayloadInspector(Inspector):
    """Inspects ``event.payload`` of events whose destination is in :attr:`destinations`.

    Match offsets are indexes into ``event.payload``. Events for other destinations are ignored.
    """

    name: str
    destinations: frozenset[Destination]

    def __init__(self, name: str, destinations: frozenset[Destination]) -> None:
        self.name = name
        self.destinations = destinations

    def handles(self, event: Event) -> bool:
        """True when this inspector is responsible for ``event``."""
        return event.destination in self.destinations

    def inspect(self, event: Event, registry: SecretRegistryProtocol) -> list[Match]:
        if not self.handles(event):
            return []
        return registry.find(event.payload)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(name={self.name!r})"
