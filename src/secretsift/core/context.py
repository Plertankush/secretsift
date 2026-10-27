"""Per-scenario run state shared between the runner, instrumentation and analysis."""

from __future__ import annotations

from dataclasses import dataclass, field

from secretsift.core.events import EventCollector
from secretsift.models import SyntheticValue
from secretsift.synthetic.registry import SecretRegistry


@dataclass
class RunContext:
    """Everything one scenario run owns. Raw values live only inside ``registry``."""

    scenario: str
    run_id: str
    seed: int | None = None
    registry: SecretRegistry = field(default_factory=SecretRegistry)
    collector: EventCollector = field(default_factory=EventCollector)
    values: dict[str, SyntheticValue] = field(default_factory=dict)

    def add_value(self, value: SyntheticValue) -> None:
        """Register a synthetic value and index it by label."""
        self.registry.register(value)
        self.values[value.label] = value
