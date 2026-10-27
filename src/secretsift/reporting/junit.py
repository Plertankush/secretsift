"""JUnit XML reporter: one testsuite per run, one testcase per scenario."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from secretsift.contracts import Reporter
from secretsift.models import Action, Finding, Report, ScenarioResult, ScenarioStatus
from secretsift.reporting.safe_io import printable

_TEXT_LIMIT = 4000
_ATTR_LIMIT = 500


def _attr(text: str) -> str:
    return printable(text, limit=_ATTR_LIMIT)


def _details(finding: Finding) -> str:
    lines = [
        f"id: {finding.id}",
        f"severity: {finding.severity.value}",
        f"category: {finding.category.value}",
        f"destination: {finding.destination.value}",
        f"component: {finding.component}",
        f"location: {finding.location or 'unknown'}",
        f"data type: {finding.data_type.value} ({finding.value_id})",
        f"expected: {finding.expected}",
        f"observed: {finding.observed}",
        f"evidence: {finding.evidence}",
        f"remediation: {finding.remediation}",
    ]
    return printable("\n".join(lines), limit=_TEXT_LIMIT, keep_newlines=True)


def _testcase(suite: ET.Element, result: ScenarioResult) -> tuple[int, int, int]:
    """Add a testcase and return (failures, errors, skipped) it contributes (0 or 1 each)."""
    case = ET.SubElement(
        suite,
        "testcase",
        classname=_attr(f"secretsift.{result.category.value}"),
        name=_attr(result.name),
        time=f"{result.duration_ms / 1000:.3f}",
    )
    denies = [f for f in result.findings if f.action is Action.DENY]
    warns = [f for f in result.findings if f.action is Action.WARN]
    outcome = (0, 0, 0)
    if denies or result.status is ScenarioStatus.FAILED:
        for finding in denies:
            failure = ET.SubElement(
                case,
                "failure",
                message=_attr(f"{finding.id}: {finding.observed}"),
                type=finding.category.value,
            )
            failure.text = _details(finding)
        if not denies:
            ET.SubElement(case, "failure", message="scenario failed", type="privacy")
        outcome = (1, 0, 0)
    elif result.status is ScenarioStatus.ERRORED:
        error = ET.SubElement(
            case, "error", message=_attr(result.error or "scenario errored"), type="scenario"
        )
        error.text = printable(result.error or "", limit=_TEXT_LIMIT, keep_newlines=True)
        outcome = (0, 1, 0)
    elif result.status is ScenarioStatus.SKIPPED:
        ET.SubElement(case, "skipped", message=_attr(result.skipped_reason or "skipped"))
        outcome = (0, 0, 1)
    if warns:
        out = ET.SubElement(case, "system-out")
        out.text = "\n\n".join(f"WARNING {_details(f)}" for f in warns)
    return outcome


class JUnitReporter(Reporter):
    """Reporter producing JUnit XML. Counts are derived from the emitted testcases."""

    format_name = "junit"

    def render(self, report: Report) -> str:
        root = ET.Element("testsuites", name="secretsift")
        suite = ET.SubElement(root, "testsuite", name="secretsift", id="0")
        props = ET.SubElement(suite, "properties")
        for name, value in (
            ("run_id", report.run_id),
            ("tool_version", report.tool_version),
            ("seed", "random" if report.seed is None else str(report.seed)),
            ("offline", str(report.coverage.offline).lower()),
        ):
            ET.SubElement(props, "property", name=name, value=_attr(value))
        failures = errors = skipped = 0
        for result in report.results:
            f, e, s = _testcase(suite, result)
            failures, errors, skipped = failures + f, errors + e, skipped + s
        total_time = sum(r.duration_ms for r in report.results) / 1000
        counts = {
            "tests": str(len(report.results)),
            "failures": str(failures),
            "errors": str(errors),
            "skipped": str(skipped),
            "time": f"{total_time:.3f}",
        }
        suite.set("timestamp", report.started_at.isoformat(timespec="seconds"))
        for target in (root, suite):
            for key, value in counts.items():
                target.set(key, value)
        ET.indent(root)
        body = ET.tostring(root, encoding="unicode")
        return '<?xml version="1.0" encoding="UTF-8"?>\n' + body + "\n"
