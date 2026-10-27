"""Hostile strings in every report field must not break out of any output format."""

from __future__ import annotations

import json
import re
import unittest
import xml.etree.ElementTree as ET

from secretsift.reporting import get_reporter
from secretsift.reporting.html_report import render_html
from tests.unit.reporting._fixtures import HOSTILE, hostile_report
from tests.unit.reporting.test_html import parse

_RAW_FRAGMENTS = ("<script", '"onmouseover=', "<img", "‮", "\x07")


class ReportEscapingTests(unittest.TestCase):
    def test_html_has_no_raw_hostile_fragments(self) -> None:
        doc = render_html(hostile_report())
        lowered = doc.lower()
        for frag in _RAW_FRAGMENTS:
            self.assertNotIn(frag, lowered)
        self.assertEqual(lowered.count("</style>"), 1)
        self.assertEqual(lowered.count("<style>"), 1)

    def test_html_hostile_text_present_escaped_in_every_field(self) -> None:
        doc = render_html(hostile_report())
        escaped = "&lt;script&gt;alert(1)&lt;/script&gt;&quot;onmouseover=&quot;x()&lt;/style&gt;"
        # run id, tool version, config, scenario, component, evidence, remediation, limitation
        self.assertGreaterEqual(doc.count(escaped), 12)
        self.assertIn("\\u202e", doc)
        self.assertIn("\\x07", doc)

    def test_html_structure_survives(self) -> None:
        parser = parse(render_html(hostile_report()))
        self.assertEqual(parser.errors, [])
        self.assertEqual(parser.stack, [])
        self.assertFalse([a for a in parser.attrs if a.startswith("on")])
        self.assertNotIn("script", parser.tags)
        self.assertNotIn("img", parser.tags)

    def test_html_attributes_cannot_be_broken(self) -> None:
        doc = render_html(hostile_report())
        attr_values = re.findall(r'(?:id|aria-label)="([^"]*)"', doc)
        self.assertTrue(attr_values)
        for value in attr_values:
            self.assertNotIn("<", value)

    def test_very_long_strings_are_bounded(self) -> None:
        self.assertLess(len(render_html(hostile_report())), 200_000)

    def test_json_round_trips_hostile_text(self) -> None:
        text = get_reporter("json").render(hostile_report())
        self.assertTrue(text.isascii())
        self.assertEqual(json.loads(text)["run_id"], HOSTILE)

    def test_junit_is_valid_xml_without_controls(self) -> None:
        text = get_reporter("junit").render(hostile_report())
        ET.fromstring(text.split("\n", 1)[1])
        self.assertNotIn("\x07", text)
        self.assertNotIn("<script", text)

    def test_terminal_has_no_escape_sequences_from_input(self) -> None:
        text = get_reporter("terminal").render(hostile_report())
        self.assertNotIn("\x07", text)
        self.assertNotIn("‮", text)
