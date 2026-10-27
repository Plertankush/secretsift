from __future__ import annotations

import os
import unittest
from unittest import mock

from secretsift.models import ScenarioStatus
from secretsift.reporting.terminal import TerminalReporter, resolve_color, verdict
from tests.unit.reporting._fixtures import hostile_report, make_report, make_result, mixed_report


class TerminalTests(unittest.TestCase):
    def test_color_on_and_off(self) -> None:
        report = mixed_report()
        self.assertIn("\x1b[", TerminalReporter(color=True).render(report))
        self.assertNotIn("\x1b", TerminalReporter(color=False).render(report))

    def test_no_color_env_and_dumb_term(self) -> None:
        with mock.patch.dict(os.environ, {"NO_COLOR": "1"}):
            self.assertFalse(resolve_color(None))
            self.assertNotIn("\x1b", TerminalReporter().render(mixed_report()))
        with mock.patch.dict(os.environ, {"TERM": "dumb"}, clear=False):
            os.environ.pop("NO_COLOR", None)
            self.assertFalse(resolve_color(None))

    def test_non_tty_is_plain(self) -> None:
        env = {k: v for k, v in os.environ.items() if k not in ("NO_COLOR", "TERM")}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch("sys.stdout") as out:
            out.isatty.return_value = False
            self.assertFalse(resolve_color(None))
            out.isatty.return_value = True
            self.assertTrue(resolve_color(None))

    def test_explicit_color_beats_env(self) -> None:
        with mock.patch.dict(os.environ, {"NO_COLOR": "1"}):
            self.assertTrue(resolve_color(True))

    def test_content(self) -> None:
        text = TerminalReporter(color=False).render(mixed_report())
        for needle in (
            "FAILED",
            "FAIL  a-fail",
            "PASS  c-pass",
            "ERROR d-err",
            "SKIP  e-skip",
            "SS-LOG-001",
            "[REDACTED:sv_0a1b2c3d]",
            "Do not log credentials.",
            "auth.py:42",
            "Limitations",
            "Uninstrumented services",
            "error: boom",
            "Findings (2)",
        ):
            self.assertIn(needle, text)

    def test_verdicts(self) -> None:
        self.assertEqual(verdict(mixed_report()), "FAILED")
        clean = make_report([make_result("ok", ScenarioStatus.PASSED, [])])
        self.assertEqual(verdict(clean), "PASSED")
        self.assertIn("none observed", TerminalReporter(color=False).render(clean))
        warned = make_report([make_result("w", ScenarioStatus.WARNED, [])])
        self.assertEqual(verdict(warned), "PASSED WITH WARNINGS")
        errored = make_report([make_result("e", ScenarioStatus.ERRORED, [])])
        self.assertEqual(verdict(errored), "ERRORED")

    def test_hostile_text_has_no_control_chars(self) -> None:
        text = TerminalReporter(color=False).render(hostile_report())
        self.assertNotIn("\x07", text)
        self.assertNotIn("‮", text)
        self.assertNotIn("\x1b", text)
        self.assertIn("\\x07", text)

    def test_wrapping_width(self) -> None:
        from tests.unit.reporting._fixtures import make_finding

        long = make_report([make_result(findings=[make_finding(observed="word " * 200)])])
        text = TerminalReporter(color=False).render(long)
        self.assertLessEqual(max(len(line) for line in text.splitlines()), 120)
