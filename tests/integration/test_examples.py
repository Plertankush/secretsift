"""Runs every offline example in-process and asserts the outcomes its README documents.

The ``local_model`` and ``hosted_api`` examples need live endpoints or accounts, so they are only
validated (parsed and cross-checked), never run.
"""

from __future__ import annotations

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path

from secretsift import cli
from secretsift.config import SecretsiftConfig, load_config, validate_config
from secretsift.core.runner import run_config
from secretsift.models import Report

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples"


def _load(name: str) -> SecretsiftConfig:
    cfg = load_config(EXAMPLES / name / "secretsift.yaml")
    absolute = [str((ROOT / p).resolve()) for p in cfg.sys_path]
    return cfg.model_copy(update={"sys_path": absolute})


def _statuses(report: Report) -> dict[str, str]:
    return {r.name: r.status.value for r in report.results}


def _destinations(report: Report, scenario: str) -> list[str]:
    return [f.destination.value for r in report.results if r.name == scenario for f in r.findings]


class ExampleOutcomeTest(unittest.TestCase):
    def test_log_leak(self) -> None:
        report = run_config(_load("log_leak"))
        self.assertEqual(_statuses(report), {"login-leaky": "failed", "login-fixed": "passed"})
        self.assertEqual(_destinations(report, "login-leaky"), ["application_logs"])
        self.assertEqual(report.exit_code, 1)

    def test_http_leak(self) -> None:
        report = run_config(_load("http_leak"))
        self.assertEqual(
            _statuses(report),
            {"lookup-leaky": "failed", "lookup-fixed": "passed", "external-call-blocked": "passed"},
        )
        self.assertEqual(_destinations(report, "lookup-leaky"), ["http_request"])
        self.assertTrue(report.coverage.offline)

    def test_ai_chat_app(self) -> None:
        report = run_config(_load("ai_chat_app"))
        leaky = {"prompt", "echo", "error", "stream"}
        expected = {f"{k}-leaky": "failed" for k in leaky}
        expected.update({f"{k}-fixed": "passed" for k in leaky})
        self.assertEqual(_statuses(report), expected)
        self.assertEqual(_destinations(report, "prompt-leaky"), ["ai_request"])
        self.assertEqual(_destinations(report, "echo-leaky"), ["ai_output"])
        self.assertEqual(_destinations(report, "stream-leaky"), ["ai_output"])
        self.assertEqual(set(_destinations(report, "error-leaky")), {"error_report"})

    def test_ci_pipeline_config_passes(self) -> None:
        report = run_config(_load("ci_pipeline"))
        self.assertEqual(_statuses(report), {"safe-login": "passed"})
        self.assertEqual(report.exit_code, 0)

    def test_reports_contain_no_raw_values(self) -> None:
        report = run_config(_load("ai_chat_app"))
        text = report.model_dump_json()
        self.assertNotIn("@example.test", text)
        self.assertIn("[REDACTED:sv_", text)

    def test_no_example_report_contains_raw_secret(self) -> None:
        for name in ("log_leak", "http_leak", "ai_chat_app", "ci_pipeline"):
            with self.subTest(example=name):
                cfg = _load(name)
                text = run_config(cfg).model_dump_json()
                for value in cfg.synthetic.values:
                    raw = getattr(value, "value", None)
                    if raw:
                        self.assertNotIn(str(raw), text)
                self.assertNotIn("@example.test", text)


class ExampleCliTest(unittest.TestCase):
    def _run(self, *argv: str) -> int:
        previous = Path.cwd()
        os.chdir(ROOT)  # example configs use sys_path relative to the repository root
        try:
            with (
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                return cli.main(list(argv))
        finally:
            os.chdir(previous)

    def test_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = ["--output-dir", tmp, "--report", "json,junit"]
            leaky = str(EXAMPLES / "log_leak" / "secretsift.yaml")
            clean = str(EXAMPLES / "ci_pipeline" / "secretsift.yaml")
            self.assertEqual(self._run("test", "-c", leaky, *out), 1)
            self.assertEqual(self._run("test", "-c", leaky, "--fail-on", "never", *out), 0)
            self.assertEqual(self._run("test", "-c", clean, *out), 0)
            self.assertTrue((Path(tmp) / "secretsift-report.json").is_file())
            self.assertTrue((Path(tmp) / "secretsift-report.xml").is_file())
            broken = Path(tmp) / "broken.yaml"
            broken.write_text(
                "version: 1\nsynthetic:\n  values:\n    - {label: k, type: synthetic_api_key}\n"
                "scenarios:\n  - name: broken\n    category: logging\n"
                "    target: 'no_such_module:fn'\n    data: [k]\n",
                encoding="utf-8",
            )
            self.assertEqual(self._run("test", "-c", str(broken), *out), 2)
            bad = Path(tmp) / "bad.yaml"
            bad.write_text("version: 2\n", encoding="utf-8")
            self.assertEqual(self._run("test", "-c", str(bad), *out), 3)

    def test_baseline_regression_flow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            leaky = str(EXAMPLES / "log_leak" / "secretsift.yaml")
            self._run("test", "-c", leaky, "--output-dir", tmp, "--report", "json")
            baseline = str(Path(tmp) / "secretsift-report.json")
            self.assertEqual(
                self._run(
                    "test",
                    "-c",
                    leaky,
                    "--baseline",
                    baseline,
                    "--output-dir",
                    tmp,
                    "--report",
                    "json",
                ),
                1,
            )


class ConfigOnlyExampleTest(unittest.TestCase):
    def test_live_endpoint_examples_validate(self) -> None:
        for name in ("local_model", "hosted_api"):
            with self.subTest(example=name):
                cfg = load_config(EXAMPLES / name / "secretsift.yaml")
                validate_config(cfg)
                self.assertTrue(cfg.scenarios)

    def test_hosted_example_is_online_and_uses_env_names_only(self) -> None:
        cfg = load_config(EXAMPLES / "hosted_api" / "secretsift.yaml")
        self.assertFalse(cfg.offline)
        self.assertTrue(cfg.network_allowlist)
        for conf in cfg.providers.values():
            self.assertIn("api_key_env", conf)
            self.assertNotIn("api_key", conf)

    def test_local_example_stays_offline(self) -> None:
        self.assertTrue(load_config(EXAMPLES / "local_model" / "secretsift.yaml").offline)

    def test_every_example_has_a_readme(self) -> None:
        for path in sorted(p for p in EXAMPLES.iterdir() if p.is_dir()):
            with self.subTest(example=path.name):
                self.assertTrue((path / "README.md").is_file())


class BasicPythonExampleTest(unittest.TestCase):
    def test_example_unittests_pass(self) -> None:
        suite = unittest.defaultTestLoader.discover(
            str(EXAMPLES / "basic_python"), top_level_dir=str(EXAMPLES / "basic_python")
        )
        out = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()):
            result = unittest.TextTestRunner(stream=out, verbosity=0).run(suite)
        self.assertEqual(result.testsRun, 3, out.getvalue())
        self.assertTrue(result.wasSuccessful(), out.getvalue())


if __name__ == "__main__":
    unittest.main()
