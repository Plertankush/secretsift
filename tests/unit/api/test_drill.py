"""Tests for the ``Drill`` SDK."""

from __future__ import annotations

import json
import logging
import tempfile
import unittest
from pathlib import Path

import secretsift
from secretsift import Drill
from secretsift.api import blocking_message
from secretsift.exceptions import ConfigError
from secretsift.instrumentation import capture
from secretsift.models import Action, Destination

_log = logging.getLogger("tests.drill")


class DrillTests(unittest.TestCase):
    def test_leaky_code_is_found_without_raw_value(self) -> None:
        with Drill(seed=7) as d:
            key = d.secret("customer_api_key", "synthetic_api_key")
            _log.warning("login with %s", key)
            self.assertTrue(d.findings)
        self.assertTrue(d.findings)  # logging record plus its stderr echo
        finding = d.findings[0]
        self.assertEqual(finding.destination, Destination.APPLICATION_LOGS)
        self.assertEqual(finding.action, Action.DENY)
        blobs = [d.report(), d.report("json"), d.report("html"), repr(d), str(finding)]
        blobs.append(json.dumps(finding.model_dump(mode="json")))
        with self.assertRaises(AssertionError) as ctx:
            d.assert_clean()
        blobs.append(str(ctx.exception))
        for blob in blobs:
            self.assertNotIn(key, blob)

    def test_safe_code_is_clean(self) -> None:
        with Drill() as d:
            key = d.secret("pw", "synthetic_password")
            _log.warning("login with %s", key[:2] + "***")
        self.assertEqual(d.findings, [])
        d.assert_clean()
        self.assertEqual(d.to_report().exit_code, 0)

    def test_print_is_captured(self) -> None:
        with Drill() as d:
            key = d.secret("tok")
            print("debug", key)
        self.assertEqual(len(d.findings), 1)
        self.assertEqual(d.findings[0].destination, Destination.APPLICATION_LOGS)

    def test_allow_rule_by_label_type_and_wildcard(self) -> None:
        for label in ("tok", "synthetic_custom", "*"):
            with Drill() as d:
                key = d.secret("tok")
                d.allow(label, "application_logs")
                _log.warning("x %s", key)
            self.assertEqual(d.findings, [], label)

    def test_allow_other_destination_still_denies(self) -> None:
        with Drill() as d:
            key = d.secret("tok")
            d.allow("tok", Destination.HTTP_REQUEST)
            _log.warning("x %s", key)
        self.assertTrue(d.findings)

    def test_warn_and_deny_override(self) -> None:
        with Drill() as d:
            key = d.secret("tok")
            d.warn("tok", "application_logs")
            _log.warning("x %s", key)
        self.assertEqual({f.action for f in d.findings}, {Action.WARN})
        d.assert_clean(allow_warn=True)
        with self.assertRaises(AssertionError):
            d.assert_clean()
        with Drill() as d:
            key = d.secret("tok")
            d.allow("*")
            d.deny("tok", "application_logs")
            _log.warning("x %s", key)
        self.assertEqual(d.findings[0].action, Action.DENY)

    def test_warn_only_policy_downgrades(self) -> None:
        with Drill(policy="warn_only") as d:
            _log.warning("x %s", d.secret("tok"))
        self.assertEqual(d.findings[0].action, Action.WARN)

    def test_cleanup_and_reuse(self) -> None:
        before = capture._STACK[:]
        d = Drill()
        with d:
            d.secret("tok")
            self.assertTrue(d.active)
        self.assertFalse(d.active)
        self.assertEqual(capture._STACK, before)
        with self.assertRaises(ConfigError):
            d.secret("late")
        with self.assertRaises(ConfigError):
            with d:
                pass
        _log.warning("after exit nothing is captured")

    def test_cleanup_on_exception(self) -> None:
        with self.assertRaises(RuntimeError):
            with Drill() as d:
                d.secret("tok")
                raise RuntimeError("boom")
        self.assertFalse(d.active)
        self.assertEqual(capture._STACK, [])

    def test_validation_errors(self) -> None:
        with self.assertRaises(ConfigError):
            Drill(policy="loose")
        with Drill() as d:
            d.secret("a")
            for bad in (
                lambda: d.secret("a"),
                lambda: d.secret("b c"),
                lambda: d.secret("b", "nope"),
                lambda: d.allow("a", "nowhere"),
                lambda: d.allow("bad label!"),
            ):
                with self.assertRaises(ConfigError):
                    bad()
        with self.assertRaises(ConfigError):
            Drill().to_report()

    def test_report_to_file_is_private_and_deterministic_seed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with Drill(seed=3) as d1:
                v1 = d1.secret("tok")
            with Drill(seed=3) as d2:
                v2 = d2.secret("tok")
            self.assertEqual(len(v1), len(v2))
            path = Path(tmp) / "r.json"
            text = d1.report("json", path)
            self.assertEqual(path.read_text(), text)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_lazy_export_and_cheap_import(self) -> None:
        self.assertIs(secretsift.Drill, Drill)
        with self.assertRaises(AttributeError):
            secretsift.nope  # noqa: B018

    def test_blocking_message(self) -> None:
        self.assertIsNone(blocking_message([]))


if __name__ == "__main__":
    unittest.main()
