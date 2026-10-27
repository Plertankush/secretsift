"""Compare two reports: which findings are new, fixed or unchanged."""

from __future__ import annotations

from dataclasses import dataclass, field

from secretsift.models import Finding, Report
from secretsift.reporting.safe_io import printable
from secretsift.reporting.terminal import resolve_color

_Key = tuple[str, str, str, str, str, str | None]


def identity_key(finding: Finding) -> _Key:
    """Run-independent identity: scenario, category, destination, component, data type, rule.

    Value ids, event ids, locations and occurrence counts change between runs and are ignored.
    """
    return (
        finding.scenario,
        finding.category.value,
        finding.destination.value,
        finding.component,
        finding.data_type.value,
        finding.rule_id,
    )


@dataclass(frozen=True)
class ReportDiff:
    """Findings only in the new report, only in the old one, or in both."""

    new: list[Finding] = field(default_factory=list)
    fixed: list[Finding] = field(default_factory=list)
    unchanged: list[Finding] = field(default_factory=list)
    old_run_id: str = ""
    new_run_id: str = ""

    @property
    def has_new(self) -> bool:
        return bool(self.new)


def diff_reports(old: Report, new: Report) -> ReportDiff:
    """``new``: in ``new`` only; ``fixed``: in ``old`` only; ``unchanged``: in both (new copy)."""
    old_keys = {identity_key(f) for f in old.findings}
    new_keys = {identity_key(f) for f in new.findings}
    new_findings = new.findings
    return ReportDiff(
        new=[f for f in new_findings if identity_key(f) not in old_keys],
        fixed=[f for f in old.findings if identity_key(f) not in new_keys],
        unchanged=[f for f in new_findings if identity_key(f) in old_keys],
        old_run_id=old.run_id,
        new_run_id=new.run_id,
    )


def _line(marker: str, finding: Finding) -> str:
    text = (
        f"{marker} {finding.id} [{finding.severity.value}] {finding.category.value} via "
        f"{finding.destination.value} in scenario {finding.scenario!r} "
        f"(component {finding.component})"
    )
    return "  " + printable(text, limit=300)


def render_diff(diff: ReportDiff, color: bool | None = None) -> str:
    """Render ``diff`` as plain text, with ANSI colors when ``color`` resolves to true."""
    use = resolve_color(color)

    def paint(text: str, code: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if use else text

    lines = [
        "secretsift report diff",
        f"  baseline: {printable(diff.old_run_id, limit=80)}",
        f"  current:  {printable(diff.new_run_id, limit=80)}",
        "",
    ]
    sections = (
        ("New findings", diff.new, "+", "31;1"),
        ("Fixed findings", diff.fixed, "-", "32"),
        ("Unchanged findings", diff.unchanged, "=", "2"),
    )
    for title, items, marker, code in sections:
        lines.append(paint(f"{title} ({len(items)})", code))
        lines.extend(paint(_line(marker, f), code) for f in items)
        if not items:
            lines.append("  none")
        lines.append("")
    verdict = f"{len(diff.new)} new, {len(diff.fixed)} fixed, {len(diff.unchanged)} unchanged"
    lines.append(paint(f"Result: {verdict}", "31;1" if diff.new else "32;1"))
    return "\n".join(lines) + "\n"
