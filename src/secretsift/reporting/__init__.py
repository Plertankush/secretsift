"""Report renderers (terminal, JSON, HTML, JUnit XML), diffing and safe file output."""

from __future__ import annotations

from pathlib import Path

from secretsift.contracts import Reporter
from secretsift.exceptions import ConfigError
from secretsift.models import Report
from secretsift.reporting.diff import ReportDiff, diff_reports, render_diff
from secretsift.reporting.html_report import HtmlReporter
from secretsift.reporting.json_report import JsonReporter
from secretsift.reporting.junit import JUnitReporter
from secretsift.reporting.safe_io import write_text_atomic
from secretsift.reporting.terminal import TerminalReporter

_REPORTERS: dict[str, type[Reporter]] = {
    "terminal": TerminalReporter,
    "json": JsonReporter,
    "html": HtmlReporter,
    "junit": JUnitReporter,
}


def get_reporter(name: str) -> Reporter:
    """Return a reporter for ``terminal``, ``json``, ``html`` or ``junit``."""
    try:
        return _REPORTERS[name.lower()]()
    except KeyError:
        known = ", ".join(sorted(_REPORTERS))
        raise ConfigError(f"unknown report format (expected one of: {known})") from None


def write_report(report: Report, fmt: str, path: str | Path) -> Path:
    """Render ``report`` as ``fmt`` and write it safely (atomic, 0o600, no symlinks)."""
    return write_text_atomic(path, get_reporter(fmt).render(report))


__all__ = [
    "HtmlReporter",
    "JUnitReporter",
    "JsonReporter",
    "ReportDiff",
    "TerminalReporter",
    "diff_reports",
    "get_reporter",
    "render_diff",
    "write_report",
]
