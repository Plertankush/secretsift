"""Plain-text terminal reporter with optional ANSI colors. Pure stdlib."""

from __future__ import annotations

import datetime as dt
import os
import sys
import textwrap
from collections.abc import Callable

from secretsift.contracts import Reporter
from secretsift.models import Action, Finding, Report, ScenarioResult, ScenarioStatus, Severity
from secretsift.reporting.safe_io import printable

_Paint = Callable[[str, str], str]
_WIDTH = 100
_FIELD_LIMIT = 2000

_STATUS_CODE = {
    ScenarioStatus.PASSED: "32",
    ScenarioStatus.FAILED: "31;1",
    ScenarioStatus.WARNED: "33",
    ScenarioStatus.ERRORED: "35",
    ScenarioStatus.SKIPPED: "2",
}
_STATUS_LABEL = {
    ScenarioStatus.PASSED: "PASS",
    ScenarioStatus.FAILED: "FAIL",
    ScenarioStatus.WARNED: "WARN",
    ScenarioStatus.ERRORED: "ERROR",
    ScenarioStatus.SKIPPED: "SKIP",
}
_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def resolve_color(color: bool | None) -> bool:
    """Decide whether to emit ANSI codes: explicit value wins, else NO_COLOR/TTY/TERM."""
    if color is not None:
        return color
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    isatty = getattr(sys.stdout, "isatty", None)
    return bool(isatty and isatty())


def verdict(report: Report) -> str:
    """Overall outcome label for a report."""
    summary = report.summary
    if summary.failed:
        return "FAILED"
    if summary.errored:
        return "ERRORED"
    if summary.warned:
        return "PASSED WITH WARNINGS"
    return "PASSED"


def _fmt_time(value: dt.datetime) -> str:
    return value.isoformat(timespec="seconds")


def _wrap(label: str, text: str, indent: int) -> list[str]:
    safe = printable(text, limit=_FIELD_LIMIT)
    prefix = " " * indent + f"{label}: "
    return textwrap.wrap(
        safe,
        width=_WIDTH,
        initial_indent=prefix,
        subsequent_indent=" " * len(prefix),
        break_long_words=True,
        break_on_hyphens=False,
    ) or [prefix.rstrip()]


class TerminalReporter(Reporter):
    """Human-readable report. ``color=None`` auto-detects (NO_COLOR, TTY, TERM=dumb)."""

    format_name = "terminal"

    def __init__(self, color: bool | None = None) -> None:
        self._color = color

    def render(self, report: Report) -> str:
        use = resolve_color(self._color)

        def paint(text: str, code: str) -> str:
            return f"\x1b[{code}m{text}\x1b[0m" if use else text

        lines: list[str] = []
        summary = report.summary
        outcome = verdict(report)
        outcome_code = {"FAILED": "31;1", "ERRORED": "35;1", "PASSED WITH WARNINGS": "33;1"}.get(
            outcome, "32;1"
        )
        duration = (report.finished_at - report.started_at).total_seconds()
        lines.append(paint(f"secretsift {printable(report.tool_version, limit=40)}", "1"))
        lines.append(f"Run:      {printable(report.run_id, limit=80)}")
        lines.append(
            f"Started:  {_fmt_time(report.started_at)}   Duration: {duration:.2f}s   "
            f"Seed: {report.seed if report.seed is not None else 'random'}"
        )
        if report.config_path:
            lines.append(f"Config:   {printable(report.config_path, limit=300)}")
        lines.append("")
        lines.append(f"Result:   {paint(outcome, outcome_code)}")
        lines.append(
            f"          {summary.total} scenarios: {summary.passed} passed, "
            f"{summary.failed} failed, {summary.warned} warned, {summary.errored} errored, "
            f"{summary.skipped} skipped; {summary.findings} findings"
        )
        lines.append("")
        lines.append(paint("Scenarios", "1"))
        for result in report.results:
            lines.append(self._scenario_line(result, paint))
            if result.error:
                lines.extend(_wrap("error", result.error, 10))
            if result.skipped_reason:
                lines.extend(_wrap("skipped", result.skipped_reason, 10))
        findings = sorted(
            report.findings,
            key=lambda f: (f.action is not Action.DENY, _SEVERITY_ORDER[f.severity], f.id),
        )
        lines.append("")
        lines.append(paint(f"Findings ({len(findings)})", "1"))
        if not findings:
            lines.append("  none observed")
        for finding in findings:
            lines.extend(self._finding_block(finding, paint))
        lines.append("")
        lines.extend(self._coverage_block(report, paint))
        return "\n".join(lines) + "\n"

    @staticmethod
    def _scenario_line(result: ScenarioResult, paint: _Paint) -> str:
        label = paint(f"{_STATUS_LABEL[result.status]:<5}", _STATUS_CODE[result.status])
        name = printable(result.name, limit=200)
        return (
            f"  {label} {name}  ({result.category.value}, {len(result.findings)} findings, "
            f"{result.events_observed} events, {result.duration_ms:.0f} ms)"
        )

    @staticmethod
    def _finding_block(finding: Finding, paint: _Paint) -> list[str]:
        code = "31;1" if finding.action is Action.DENY else "33"
        head = (
            f"{finding.id}  {finding.severity.value.upper()}  {finding.action.value.upper()}  "
            f"{finding.category.value}"
        )
        occurrences = f" (x{finding.occurrences})" if finding.occurrences > 1 else ""
        where = printable(finding.component, limit=200)
        if finding.location:
            where += f" @ {printable(finding.location, limit=200)}"
        out = ["", "  " + paint(printable(head, limit=200), code) + occurrences]
        out.extend(_wrap("scenario", finding.scenario, 4))
        out.extend(_wrap("expected", finding.expected, 4))
        out.extend(_wrap("observed", finding.observed, 4))
        out.extend(_wrap("where", f"{finding.destination.value} / {where}", 4))
        out.extend(
            _wrap(
                "data",
                f"{finding.data_type.value} ({finding.value_id}), matched as "
                f"{finding.variant.value}, {finding.confidence}",
                4,
            )
        )
        out.extend(_wrap("evidence", finding.evidence, 4))
        out.extend(_wrap("fix", finding.remediation, 4))
        return out

    @staticmethod
    def _coverage_block(report: Report, paint: _Paint) -> list[str]:
        cov = report.coverage
        destinations = ", ".join(d.value for d in cov.destinations_observed) or "none"
        inspectors = ", ".join(printable(i, limit=80) for i in cov.inspectors_active) or "none"
        out = [paint("Coverage", "1")]
        out.append(f"  inspectors:   {inspectors}")
        out.append(f"  destinations: {destinations}")
        out.append(f"  offline mode: {'yes' if cov.offline else 'no'}")
        out.append(paint("Limitations", "1"))
        if not cov.limitations:
            out.append("  none declared")
        for item in cov.limitations:
            out.extend(_wrap("-", item, 2))
        out.append("")
        out.append(
            "A clean result only covers what secretsift observed; see the limitations above."
        )
        return out
