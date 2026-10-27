"""Assertion helper for tests that must not leak synthetic data."""

from __future__ import annotations

from collections.abc import Sequence

from secretsift.models import Action, Finding


def assert_no_findings(findings: Sequence[Finding], *, allow_warn: bool = False) -> None:
    """Raise ``AssertionError`` (redacted message) if any blocking finding exists."""
    blocking = [f for f in findings if not (allow_warn and f.action is Action.WARN)]
    if not blocking:
        return
    lines = [f"secretsift: {len(blocking)} privacy finding(s)"]
    for f in blocking:
        where = f"{f.component}@{f.location}" if f.location else f.component
        lines.append(
            f"  [{f.id}] {f.action.value}/{f.severity.value} {f.destination.value} "
            f"in {where} (scenario {f.scenario!r}, value {f.value_id}, x{f.occurrences})"
        )
        lines.append(f"      evidence: {f.evidence}")
        lines.append(f"      fix: {f.remediation}")
    raise AssertionError("\n".join(lines))
