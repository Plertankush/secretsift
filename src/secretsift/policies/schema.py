"""Declarative policy models (as written in the YAML ``policy:`` section)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from secretsift.models import Action


class Rule(BaseModel):
    """One policy rule. ``data`` is a label, a DataType value or ``*``."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=64)
    data: str = "*"
    destination: str = "*"
    action: Action
    severity: str | None = None
    scenario: str | None = None
    remediation: str | None = None
    reason: str | None = None


class PolicyConfig(BaseModel):
    """Policy section: mode, default action and rules."""

    model_config = ConfigDict(extra="forbid")

    mode: Literal["strict", "warn_only"] = "strict"
    default_action: Action = Action.DENY
    rules: list[Rule] = Field(default_factory=list)
