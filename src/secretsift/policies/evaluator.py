"""Policy decision engine."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from secretsift.models import (
    WILDCARD,
    Action,
    Decision,
    Destination,
    Event,
    Severity,
    SyntheticValue,
)

_DEFAULT_SEVERITY = {
    Action.DENY: Severity.MEDIUM,
    Action.WARN: Severity.LOW,
    Action.ALLOW: Severity.INFO,
}


@dataclass(frozen=True)
class CompiledRule:
    """A validated rule. ``data_kind`` is ``label``, ``type`` or ``any``."""

    id: str
    scenario: str | None
    data_kind: str
    data: str
    destination: str
    action: Action
    severity: Severity | None
    remediation: str | None
    reason: str | None


class PolicyEvaluator:
    """Implements ``PolicyEvaluatorProtocol``; build it with ``compile_policy``."""

    def __init__(
        self,
        rules: list[CompiledRule],
        *,
        mode: str = "strict",
        default_action: Action = Action.DENY,
        approved_destinations: Mapping[str, frozenset[Destination]] | None = None,
    ) -> None:
        self._rules = list(rules)
        self._mode = mode
        self._default = default_action
        self._approved = dict(approved_destinations or {})

    def __repr__(self) -> str:
        return f"PolicyEvaluator(rules={len(self._rules)}, mode={self._mode!r})"

    @property
    def rule_ids(self) -> list[str]:
        return [r.id for r in self._rules]

    def remediation_for_rule(self, rule_id: str | None) -> str | None:
        """Rule-specific remediation text, if the rule declares one."""
        for r in self._rules:
            if r.id == rule_id:
                return r.remediation
        return None

    def _finalize(
        self, action: Action, rule_id: str | None, reason: str, severity: Severity | None
    ) -> Decision:
        if action is Action.DENY and self._mode == "warn_only":
            action = Action.WARN
            reason += " (downgraded to warn by warn_only mode)"
        sev = severity if severity is not None else _DEFAULT_SEVERITY[action]
        return Decision(action=action, rule_id=rule_id, reason=reason, severity=sev)

    def decide(self, scenario: str, value: SyntheticValue, event: Event) -> Decision:
        dest = event.destination
        if event.approved:
            return Decision(
                action=Action.ALLOW,
                rule_id=None,
                reason="event is an approved sink",
                severity=Severity.INFO,
            )
        if dest is Destination.APPROVED_TEST_INPUT:
            return Decision(
                action=Action.ALLOW,
                rule_id=None,
                reason="approved test input",
                severity=Severity.INFO,
            )
        if dest in self._approved.get(scenario, frozenset()):
            return Decision(
                action=Action.ALLOW,
                rule_id=None,
                reason=f"destination {dest.value} is approved for scenario {scenario!r}",
                severity=Severity.INFO,
            )
        best: CompiledRule | None = None
        best_key = (-1, -1, -1)
        for r in self._rules:
            if r.scenario is not None and r.scenario != scenario:
                continue
            if r.data_kind == "label":
                if r.data != value.label:
                    continue
                data_rank = 2
            elif r.data_kind == "type":
                if r.data != value.data_type.value:
                    continue
                data_rank = 1
            else:
                data_rank = 0
            if r.destination != WILDCARD and r.destination != dest.value:
                continue
            dest_rank = 0 if r.destination == WILDCARD else 1
            key = (1 if r.scenario is not None else 0, data_rank, dest_rank)
            if key > best_key:
                best, best_key = r, key
        if best is None:
            return self._finalize(
                self._default,
                None,
                f"no rule matched {value.label} at {dest.value}; default action applied",
                None,
            )
        reason = best.reason or (
            f"rule {best.id}: {best.action.value} {value.label} at {dest.value}"
        )
        return self._finalize(best.action, best.id, reason, best.severity)
