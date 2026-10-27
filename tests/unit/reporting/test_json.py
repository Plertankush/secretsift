from __future__ import annotations

import json
import unittest

from secretsift.exceptions import ConfigError
from secretsift.reporting import json_report
from tests.unit.reporting._fixtures import hostile_report, mixed_report


class JsonReportTests(unittest.TestCase):
    def test_round_trip_equality(self) -> None:
        for report in (mixed_report(), hostile_report()):
            self.assertEqual(json_report.loads(json_report.dumps(report)), report)

    def test_schema_marker_first_and_ascii(self) -> None:
        text = json_report.dumps(hostile_report())
        self.assertTrue(text.isascii())
        self.assertEqual(next(iter(json.loads(text))), "$schema")
        self.assertEqual(json.loads(text)["$schema"], "secretsift-report/1")

    def test_rejects_wrong_schema_version(self) -> None:
        data = json_report.to_dict(mixed_report())
        data["schema_version"] = "2"
        with self.assertRaises(ConfigError):
            json_report.loads(json.dumps(data))

    def test_rejects_wrong_schema_id(self) -> None:
        data = json_report.to_dict(mixed_report())
        data["$schema"] = "other/9"
        with self.assertRaises(ConfigError):
            json_report.loads(json.dumps(data))

    def test_rejects_oversize(self) -> None:
        with self.assertRaises(ConfigError):
            json_report.loads(" " * (json_report.MAX_REPORT_CHARS + 1))

    def test_rejects_garbage(self) -> None:
        for text in ("not json", "[]", "{}", "[" * 100000):
            with self.assertRaises(ConfigError):
                json_report.loads(text)

    def test_schema_error_does_not_echo_values(self) -> None:
        data = json_report.to_dict(mixed_report())
        data["run_id"] = 12345
        data["seed"] = "TOPSECRETVALUE"
        with self.assertRaises(ConfigError) as ctx:
            json_report.loads(json.dumps(data))
        self.assertNotIn("TOPSECRETVALUE", str(ctx.exception))

    def test_unknown_fields_rejected(self) -> None:
        data = json_report.to_dict(mixed_report())
        data["extra"] = 1
        with self.assertRaises(ConfigError):
            json_report.loads(json.dumps(data))

    def test_reporter_matches_dumps(self) -> None:
        report = mixed_report()
        self.assertEqual(json_report.JsonReporter().render(report), json_report.dumps(report))
