"""Scenario specification and ``{{ label }}`` input templating."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from secretsift.exceptions import ConfigError
from secretsift.models import Category, Destination, SyntheticValue

LABEL_PATTERN = r"[A-Za-z_][A-Za-z0-9_.-]*"
_TEMPLATE = re.compile(r"\{\{\s*(" + LABEL_PATTERN + r")\s*\}\}")
_TARGET = re.compile(r"^[A-Za-z_][\w.]*:[A-Za-z_][\w.]*$")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. -]*$")

_SCENARIO_CATEGORIES = (
    Category.LOGGING,
    Category.NETWORK,
    Category.AI_CONTEXT,
    Category.RESPONSE,
    Category.STORAGE,
)


class ScenarioSpec(BaseModel):
    """One privacy scenario: a target callable plus the data planted into its inputs."""

    model_config = ConfigDict(extra="forbid")

    name: str
    category: Category
    target: str
    inputs: dict[str, Any] = Field(default_factory=dict)
    data: list[str] | None = None
    provider: str | None = None
    storage_paths: list[str] = Field(default_factory=list)
    expect_exception: bool = False
    approved_destinations: list[Destination] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def _check_name(cls, v: str) -> str:
        if not _NAME.match(v) or len(v) > 100:
            raise ValueError("name must be 1-100 chars of letters, digits, space, '_', '.', '-'")
        return v

    @field_validator("category")
    @classmethod
    def _check_category(cls, v: Category) -> Category:
        if v not in _SCENARIO_CATEGORIES:
            allowed = ", ".join(c.value for c in _SCENARIO_CATEGORIES)
            raise ValueError(f"category must be one of: {allowed}")
        return v

    @field_validator("target")
    @classmethod
    def _check_target(cls, v: str) -> str:
        if not _TARGET.match(v):
            raise ValueError("target must look like 'package.module:callable'")
        return v


def _render(node: Any, values: Mapping[str, str]) -> Any:
    if isinstance(node, str):

        def sub(m: re.Match[str]) -> str:
            label = m.group(1)
            if label not in values:
                raise ConfigError(f"unknown label {label!r} in input template")
            return values[label]

        return _TEMPLATE.sub(sub, node)
    if isinstance(node, dict):
        return {k: _render(v, values) for k, v in node.items()}
    if isinstance(node, (list, tuple)):
        return [_render(v, values) for v in node]
    return node


def render_inputs(
    inputs: Mapping[str, Any], values_by_label: Mapping[str, SyntheticValue | str]
) -> dict[str, Any]:
    """Substitute ``{{ label }}`` with the raw synthetic value, deeply over dict/list/str."""
    raw = {k: (v if isinstance(v, str) else v.value) for k, v in values_by_label.items()}
    rendered: dict[str, Any] = _render(dict(inputs), raw)
    return rendered
