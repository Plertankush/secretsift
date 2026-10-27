from __future__ import annotations

import unittest
from html.parser import HTMLParser

from secretsift.models import ScenarioStatus
from secretsift.reporting import get_reporter
from secretsift.reporting.html_report import render_html
from tests.unit.reporting._fixtures import hostile_report, make_report, make_result, mixed_report

_VOID = {"meta", "link", "br", "img", "hr", "input", "circle", "rect", "path"}


class _Balance(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.stack: list[str] = []
        self.errors: list[str] = []
        self.tags: list[str] = []
        self.attrs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        self.attrs.extend(name for name, _ in attrs)
        if tag not in _VOID:
            self.stack.append(tag)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        self.attrs.extend(name for name, _ in attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag in _VOID:
            return
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(f"unexpected </{tag}> with stack {self.stack[-3:]}")
            return
        self.stack.pop()


def parse(doc: str) -> _Balance:
    parser = _Balance()
    parser.feed(doc)
    parser.close()
    return parser


class HtmlReportTests(unittest.TestCase):
    def test_well_formed_for_varied_reports(self) -> None:
        for report in (mixed_report(), hostile_report(), make_report([]), make_report()):
            parser = parse(render_html(report))
            self.assertEqual(parser.errors, [])
            self.assertEqual(parser.stack, [])

    def test_no_scripts_or_external_resources(self) -> None:
        for report in (mixed_report(), hostile_report()):
            doc = render_html(report).lower()
            self.assertNotIn("<script", doc)
            self.assertNotIn("http://", doc)
            self.assertNotIn("https://", doc)
            self.assertNotIn("@import", doc)
            self.assertNotIn("url(", doc)
            self.assertFalse([a for a in parse(doc).attrs if a.startswith("on")])

    def test_csp_meta_present_and_restrictive(self) -> None:
        doc = render_html(mixed_report())
        self.assertIn('http-equiv="Content-Security-Policy"', doc)
        self.assertIn("default-src &#x27;none&#x27;", doc)
        self.assertNotIn("script-src", doc)

    def test_sections_present(self) -> None:
        doc = render_html(mixed_report())
        for text in (
            "Scenario outcomes",
            "Findings by category",
            "Findings by severity",
            "<table>",
            "SS-LOG-001",
            "Redacted evidence",
            "Remediation",
            "Coverage and limitations",
            "Uninstrumented services",
            "prefers-color-scheme:dark",
            "<svg",
        ):
            self.assertIn(text, doc)

    def test_verdict_pill(self) -> None:
        self.assertIn("pill failed", render_html(mixed_report()))
        clean = make_report([make_result("ok", ScenarioStatus.PASSED, [])])
        self.assertIn("pill passed", render_html(clean))

    def test_empty_report_renders(self) -> None:
        doc = render_html(make_report([]))
        self.assertIn("No scenarios were run.", doc)
        self.assertIn("No findings observed.", doc)

    def test_long_evidence_is_collapsible(self) -> None:
        from tests.unit.reporting._fixtures import make_finding

        short = render_html(make_report())
        self.assertNotIn("<details>", short)
        long = make_report([make_result(findings=[make_finding(evidence="e" * 900)])])
        self.assertIn("<details>", render_html(long))

    def test_reporter_registry(self) -> None:
        self.assertEqual(get_reporter("html").format_name, "html")
        self.assertIn("<!doctype html>", get_reporter("html").render(make_report()))

    def test_donut_segments_match_counts(self) -> None:
        doc = render_html(mixed_report())
        self.assertEqual(doc.count('class="donut-seg"'), 5)
        self.assertIn("1 passed, 1 warned, 1 failed, 1 errored, 1 skipped", doc)
