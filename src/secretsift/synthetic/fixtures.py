"""Helpers to build sets of synthetic values."""

from __future__ import annotations

from collections.abc import Iterable

from secretsift.exceptions import ConfigError
from secretsift.models import DataType, SyntheticValue
from secretsift.synthetic.generator import generate_value


def generate_set(
    specs: Iterable[tuple[str, DataType]], run_id: str, seed: int | None
) -> list[SyntheticValue]:
    """Generate one value per ``(label, type)`` pair; labels must be unique."""
    values: list[SyntheticValue] = []
    seen: set[str] = set()
    for label, data_type in specs:
        if label in seen:
            raise ConfigError(f"duplicate synthetic label: {label!r}")
        seen.add(label)
        values.append(generate_value(label, data_type, run_id=run_id, seed=seed))
    return values
