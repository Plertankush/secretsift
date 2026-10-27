"""Turns observed events into policy-evaluated findings. Raw values never leave this module."""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from secretsift.contracts import Inspector, PolicyEvaluatorProtocol, SecretRegistryProtocol
from secretsift.evidence.redaction import build_evidence
from secretsift.models import (
    Action,
    Category,
    Destination,
    Event,
    Finding,
    Match,
    Variant,
)
from secretsift.policies.rules import remediation_for

_CATEGORY: dict[Destination, Category] = {
    Destination.APPLICATION_LOGS: Category.LOGGING,
    Destination.ERROR_REPORT: Category.LOGGING,
    Destination.HTTP_REQUEST: Category.NETWORK,
    Destination.AI_REQUEST: Category.AI_CONTEXT,
    Destination.AI_OUTPUT: Category.RESPONSE,
    Destination.STORAGE: Category.STORAGE,
}

_PREFIX: dict[Category, str] = {
    Category.LOGGING: "LOG",
    Category.NETWORK: "NET",
    Category.AI_CONTEXT: "CTX",
    Category.RESPONSE: "RSP",
    Category.STORAGE: "STO",
    Category.REGRESSION: "REG",
}

_DedupKey = tuple[str, str, Destination, str, str | None]


def category_for(destination: Destination) -> Category | None:
    """Finding category for a destination; ``None`` for destinations that are never findings."""
    return _CATEGORY.get(destination)


def id_prefix(category: Category) -> str:
    """Three-letter code used in finding ids."""
    return _PREFIX[category]


def format_finding_id(category: Category, number: int) -> str:
    """Build ``SS-<CODE>-<NNN>``."""
    return f"SS-{_PREFIX[category]}-{number:03d}"


def _first_per_value(matches: list[Match]) -> list[Match]:
    """One match per value id (raw variant preferred), in order of first appearance."""
    chosen: dict[str, Match] = {}
    for m in matches:
        cur = chosen.get(m.value_id)
        if cur is None or (cur.variant is not Variant.RAW and m.variant is Variant.RAW):
            chosen[m.value_id] = m
    return list(chosen.values())


def analyze(
    scenario: str,
    events: Iterable[Event],
    registry: SecretRegistryProtocol,
    inspectors: Sequence[Inspector],
    evaluator: PolicyEvaluatorProtocol,
    collector_dropped: int = 0,
) -> list[Finding]:
    """Evaluate every event and return deduplicated findings in deterministic order.

    Events are processed in input order, except that streaming aggregate events
    (``metadata["aggregated"] is True``) are processed last so they never duplicate a
    per-chunk finding for the same value and component. ``collector_dropped`` is accepted
    for signature stability; dropped-event accounting is the caller's responsibility.
    """
    del collector_dropped
    ordered = list(events)
    chunks = [e for e in ordered if e.metadata.get("aggregated") is not True]
    aggregates = [e for e in ordered if e.metadata.get("aggregated") is True]
    findings: list[Finding] = []
    index: dict[_DedupKey, int] = {}
    counters: dict[Category, int] = {}
    covered: set[tuple[str, str, Destination]] = set()

    def process(event: Event, aggregated: bool) -> None:
        category = _CATEGORY.get(event.destination)
        if category is None:
            return
        found: list[tuple[Match, str]] = []
        for inspector in inspectors:
            if event.destination in inspector.destinations:
                found.extend((m, inspector.name) for m in inspector.inspect(event, registry))
        methods: dict[str, str] = {}
        for m, name in found:
            methods.setdefault(m.value_id, name)
        for match in _first_per_value(sorted((m for m, _ in found), key=lambda m: m.start)):
            if aggregated and (match.value_id, event.component, event.destination) in covered:
                continue
            value = registry.get(match.value_id)
            decision = evaluator.decide(scenario, value, event)
            if decision.action is Action.ALLOW:
                continue
            key: _DedupKey = (
                scenario,
                match.value_id,
                event.destination,
                event.component,
                event.location,
            )
            if key in index:
                prior = findings[index[key]]
                findings[index[key]] = prior.model_copy(
                    update={"occurrences": prior.occurrences + 1}
                )
                continue
            counters[category] = counters.get(category, 0) + 1
            remediation = None
            rule_text = getattr(evaluator, "remediation_for_rule", None)
            if callable(rule_text) and decision.rule_id is not None:
                remediation = rule_text(decision.rule_id)
            where = event.destination.value
            index[key] = len(findings)
            findings.append(
                Finding(
                    id=format_finding_id(category, counters[category]),
                    rule_id=decision.rule_id,
                    scenario=scenario,
                    category=category,
                    severity=decision.severity,
                    action=decision.action,
                    expected=f"{value.label} ({value.data_type.value}) must not reach {where}",
                    observed=f"{value.label} observed in {where} via {event.component}",
                    component=event.component,
                    location=event.location,
                    destination=event.destination,
                    data_type=value.data_type,
                    value_id=value.id,
                    variant=match.variant,
                    evidence=build_evidence(event, [match], registry),
                    detection_method=methods[match.value_id],
                    confidence="exact" if match.variant is Variant.RAW else "normalized",
                    remediation=remediation or remediation_for(event.destination),
                    event_id=event.id,
                )
            )
            if not aggregated:
                covered.add((match.value_id, event.component, event.destination))

    for event in chunks:
        process(event, False)
    for event in aggregates:
        process(event, True)
    return findings
