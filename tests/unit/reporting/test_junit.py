from __future__ import annotations

import unittest
import xml.etree.ElementTree as ET

from secretsift.models import ScenarioStatus
from secretsift.reporting.junit import JUnitReporter
from tests.unit.reporting._fixtures import hostile_report, make_report, make_result, mixed_report


def parse(report_text: str) -> ET.Element:
    return ET.fromstring(report_text.split("\n", 1)[1])


class JUnitTests(unittest.TestCase):
    def test_counts_and_structure(self) -> None:
        root = parse(JUnitReporter().render(mixed_report()))
        suite = root.find("testsuite")
        assert suite is not None
        self.assertEqual(len(suite.findall("testcase")), 5)
        for node in (root, suite):
            self.assertEqual(
                (node.get("tests"), node.get("failures"), node.get("errors"), node.get("skipped")),
                ("5", "1", "1", "1"),
            )
        self.assertEqual(len(suite.findall(".//failure")), 1)
        self.assertEqual(len(suite.findall(".//error")), 1)
        self.assertEqual(len(suite.findall(".//skipped")), 1)

    def test_warn_goes_to_system_out_not_failure(self) -> None:
        root = parse(JUnitReporter().render(mixed_report()))
        case = next(c for c in root.iter("testcase") if c.get("name") == "b-warn")
        self.assertIsNone(case.find("failure"))
        out = case.find("system-out")
        assert out is not None and out.text is not None
        self.assertIn("SS-NET-001", out.text)

    def test_failure_per_deny_finding(self) -> None:
        from tests.unit.reporting._fixtures import make_finding

        two = make_result(findings=[make_finding(), make_finding(id="SS-LOG-002")])
        root = parse(JUnitReporter().render(make_report([two])))
        self.assertEqual(len(list(root.iter("failure"))), 2)
        self.assertEqual(root.get("failures"), "1")

    def test_clean_report(self) -> None:
        clean = make_report([make_result("ok", ScenarioStatus.PASSED, [])])
        root = parse(JUnitReporter().render(clean))
        self.assertEqual((root.get("tests"), root.get("failures")), ("1", "0"))

    def test_hostile_content_is_valid_xml(self) -> None:
        text = JUnitReporter().render(hostile_report())
        root = parse(text)
        self.assertEqual(root.get("tests"), "3")
        self.assertNotIn("\x07", text)
        self.assertNotIn("‮", text)
        self.assertNotIn("<script", text)

    def test_declaration(self) -> None:
        self.assertTrue(JUnitReporter().render(make_report()).startswith("<?xml version"))
