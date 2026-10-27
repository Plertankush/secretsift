"""Baseline comparison between two reports."""

from __future__ import annotations

from dataclasses import dataclass, field

from secretsift.core.analysis import format_finding_id
from secretsift.models import Category, Finding, Report

IdentityKey = tuple[str, str, str, str, str, str | None]


@dataclass(frozen=True)
class BaselineDiff:
    """New, fixed and unchanged findings between a baseline and a new report."""

    new: list[Finding] = field(default_factory=list)
    fixed: list[Finding] = field(default_factory=list)
    unchanged: list[Finding] = field(default_factory=list)


def identity_key(finding: Finding) -> IdentityKey:
    """Run-stable identity: excludes the run-specific ``value_id`` (data type stands in)."""
    return (
        finding.scenario,
        finding.category.value,
        finding.destination.value,
        finding.component,
        finding.data_type.value,
        finding.rule_id,
    )


def compare_to_baseline(old: Report, new: Report) -> BaselineDiff:
    """Diff findings by identity key. ``unchanged`` and ``new`` come from ``new``'s findings."""
    old_findings = old.findings
    new_findings = new.findings
    old_keys = {identity_key(f) for f in old_findings}
    new_keys = {identity_key(f) for f in new_findings}
    return BaselineDiff(
        new=[f for f in new_findings if identity_key(f) not in old_keys],
        fixed=[f for f in old_findings if identity_key(f) not in new_keys],
        unchanged=[f for f in new_findings if identity_key(f) in old_keys],
    )


def regression_findings(diff: BaselineDiff) -> list[Finding]:
    """New findings re-labelled as regressions with sequential ``SS-REG-NNN`` ids."""
    return [
        f.model_copy(
            update={
                "category": Category.REGRESSION,
                "id": format_finding_id(Category.REGRESSION, i),
            }
        )
        for i, f in enumerate(diff.new, start=1)
    ]
