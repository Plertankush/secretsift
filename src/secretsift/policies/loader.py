"""Compile a declarative policy into a validated evaluator."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from secretsift.exceptions import PolicyError
from secretsift.models import WILDCARD, DataType, Destination, Severity
from secretsift.policies.evaluator import CompiledRule, PolicyEvaluator
from secretsift.policies.schema import PolicyConfig


def _enum_values(e: type[Destination] | type[Severity] | type[DataType]) -> str:
    return ", ".join(m.value for m in e)


def compile_policy(
    policy: PolicyConfig,
    declared_labels: set[str],
    labels_to_types: dict[str, DataType],
    *,
    scenario_names: Iterable[str] | None = None,
    approved_destinations: Mapping[str, Iterable[Destination]] | None = None,
) -> PolicyEvaluator:
    """Validate ``policy`` and return an evaluator; raises ``PolicyError`` on any problem."""
    names = set(scenario_names) if scenario_names is not None else None
    types = {t.value for t in DataType}
    seen_ids: set[str] = set()
    seen_keys: dict[tuple[str | None, str, str, str], tuple[str, str]] = {}
    compiled: list[CompiledRule] = []
    for rule in policy.rules:
        rid = rule.id
        if rid in seen_ids:
            raise PolicyError(f"duplicate rule id {rid!r}")
        seen_ids.add(rid)
        if rule.destination != WILDCARD and rule.destination not in {d.value for d in Destination}:
            raise PolicyError(
                f"rule {rid!r}: unknown destination {rule.destination!r}; "
                f"expected '*' or one of: {_enum_values(Destination)}"
            )
        if rule.data == WILDCARD:
            kind = "any"
        elif rule.data in declared_labels:
            kind = "label"
        elif rule.data in types:
            kind = "type"
        else:
            raise PolicyError(
                f"rule {rid!r}: unknown data {rule.data!r}; expected a declared label, "
                f"a data type ({_enum_values(DataType)}) or '*'"
            )
        if kind == "label" and rule.data not in labels_to_types:
            raise PolicyError(f"rule {rid!r}: label {rule.data!r} has no data type")
        if rule.scenario is not None and names is not None and rule.scenario not in names:
            raise PolicyError(f"rule {rid!r}: unknown scenario {rule.scenario!r}")
        severity: Severity | None = None
        if rule.severity is not None:
            try:
                severity = Severity(rule.severity.lower())
            except ValueError:
                raise PolicyError(
                    f"rule {rid!r}: invalid severity {rule.severity!r}; "
                    f"expected one of: {_enum_values(Severity)}"
                ) from None
        key = (rule.scenario, kind, rule.data, rule.destination)
        prior = seen_keys.get(key)
        if prior is not None and prior[1] != rule.action.value:
            raise PolicyError(
                f"rules {prior[0]!r} and {rid!r} conflict: same scenario, data and "
                f"destination but different actions ({prior[1]} vs {rule.action.value})"
            )
        seen_keys.setdefault(key, (rid, rule.action.value))
        compiled.append(
            CompiledRule(
                id=rid,
                scenario=rule.scenario,
                data_kind=kind,
                data=rule.data,
                destination=rule.destination,
                action=rule.action,
                severity=severity,
                remediation=rule.remediation,
                reason=rule.reason,
            )
        )
    approved: dict[str, frozenset[Destination]] = {}
    for scen, dests in (approved_destinations or {}).items():
        if names is not None and scen not in names:
            raise PolicyError(f"approved_destinations for unknown scenario {scen!r}")
        approved[scen] = frozenset(Destination(d) for d in dests)
    return PolicyEvaluator(
        compiled,
        mode=policy.mode,
        default_action=policy.default_action,
        approved_destinations=approved,
    )
