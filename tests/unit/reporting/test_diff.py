from __future__ import annotations

import unittest

from secretsift.models import Category, Destination, ScenarioStatus
from secretsift.reporting.diff import diff_reports, identity_key, render_diff
from tests.unit.reporting._fixtures import hostile_report, make_finding, make_report, make_result


def rep(*findings_by_scenario: tuple[str, list]) -> object:
    return make_report(
        [make_result(n, ScenarioStatus.FAILED, fs) for n, fs in findings_by_scenario]
    )


class DiffTests(unittest.TestCase):
    def test_new_fixed_unchanged(self) -> None:
        keep = make_finding(scenario="s1")
        gone = make_finding(scenario="s2", id="SS-LOG-002")
        added = make_finding(scenario="s3", id="SS-LOG-003", destination=Destination.AI_REQUEST)
        old = rep(("s1", [keep]), ("s2", [gone]))
        new = rep(
            ("s1", [keep.model_copy(update={"value_id": "sv_ffffffff", "id": "SS-LOG-009"})]),
            ("s3", [added]),
        )
        d = diff_reports(old, new)  # type: ignore[arg-type]
        self.assertEqual([f.scenario for f in d.new], ["s3"])
        self.assertEqual([f.scenario for f in d.fixed], ["s2"])
        self.assertEqual([f.scenario for f in d.unchanged], ["s1"])
        self.assertTrue(d.has_new)

    def test_identity_ignores_run_specific_fields(self) -> None:
        a = make_finding()
        b = make_finding(value_id="sv_99999999", id="SS-LOG-050", location="x.py:1", occurrences=4)
        self.assertEqual(identity_key(a), identity_key(b))
        self.assertNotEqual(identity_key(a), identity_key(make_finding(category=Category.NETWORK)))
        self.assertNotEqual(identity_key(a), identity_key(make_finding(rule_id="R2")))

    def test_identical_reports(self) -> None:
        r = make_report()
        d = diff_reports(r, r)
        self.assertEqual((len(d.new), len(d.fixed), len(d.unchanged)), (0, 0, 1))
        self.assertFalse(d.has_new)

    def test_render_plain_and_color(self) -> None:
        old = make_report([make_result(findings=[])])
        d = diff_reports(old, make_report())
        plain = render_diff(d, color=False)
        self.assertNotIn("\x1b", plain)
        self.assertIn("New findings (1)", plain)
        self.assertIn("Fixed findings (0)", plain)
        self.assertIn("Result: 1 new, 0 fixed, 0 unchanged", plain)
        self.assertIn("\x1b[", render_diff(d, color=True))

    def test_render_hostile(self) -> None:
        d = diff_reports(make_report([]), hostile_report())
        text = render_diff(d, color=False)
        self.assertNotIn("\x07", text)
        self.assertNotIn("‮", text)
