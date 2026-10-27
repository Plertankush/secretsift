"""CLI tests: call ``cli.main`` in-process inside a temporary working directory."""

from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from secretsift import cli
from secretsift.config import dump_default_config

FAKE_KEY = "sk-fake-DO-NOT-LEAK-1234567890"


class CliCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        self._cwd = os.getcwd()
        os.chdir(self.dir)
        self.addCleanup(os.chdir, self._cwd)

    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def init_config(self) -> None:
        if not (self.dir / "secretsift.yaml").exists():
            self.assertEqual(self.run_cli("init")[0], 0)


class InitTests(CliCase):
    def test_init_writes_and_refuses_overwrite(self) -> None:
        code, out, _ = self.run_cli("init")
        self.assertEqual(code, 0)
        self.assertEqual((self.dir / "secretsift.yaml").read_text(), dump_default_config())
        (self.dir / "secretsift.yaml").write_text("keep me")
        code, _, err = self.run_cli("init")
        self.assertEqual(code, 3)
        self.assertIn("--force", err)
        self.assertEqual((self.dir / "secretsift.yaml").read_text(), "keep me")

    def test_init_force_and_custom_path(self) -> None:
        self.run_cli("init", "other.yaml")
        self.assertTrue((self.dir / "other.yaml").exists())
        (self.dir / "other.yaml").write_text("x")
        self.assertEqual(self.run_cli("init", "other.yaml", "--force")[0], 0)
        self.assertEqual((self.dir / "other.yaml").read_text(), dump_default_config())


class ValidateTests(CliCase):
    def test_valid(self) -> None:
        self.init_config()
        code, out, _ = self.run_cli("validate")
        self.assertEqual(code, 0)
        self.assertIn("config OK", out)

    def test_invalid_config_exits_3(self) -> None:
        (self.dir / "secretsift.yaml").write_text("version: 2\n")
        code, out, err = self.run_cli("validate")
        self.assertEqual(code, 3)
        self.assertNotIn("Traceback", err)
        self.assertIn("error:", err)

    def test_missing_config_exits_3(self) -> None:
        self.assertEqual(self.run_cli("validate")[0], 3)

    def test_warnings_printed_to_stderr(self) -> None:
        (self.dir / "secretsift.yaml").write_text("version: 1\n")
        code, _, err = self.run_cli("validate")
        self.assertEqual(code, 0)
        self.assertIn("warning: no scenarios defined", err)


class TestCommandTests(CliCase):
    def test_starter_config_finds_leak_and_writes_private_files(self) -> None:
        self.init_config()
        code, out, err = self.run_cli("test", "--no-color")
        self.assertEqual(code, 1)
        self.assertIn("leaky-login", out)
        for name in ("secretsift-report.json", "secretsift-report.html"):
            path = self.dir / "secretsift-reports" / name
            self.assertTrue(path.exists(), name)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertNotIn("\x1b[", out)

    def test_fail_on_never(self) -> None:
        self.init_config()
        self.assertEqual(self.run_cli("test", "--fail-on", "never")[0], 0)

    def test_filter_skips_other_categories(self) -> None:
        self.init_config()
        code, out, _ = self.run_cli("test", "--filter", "network", "--report", "terminal")
        self.assertEqual(code, 0)
        code, _, err = self.run_cli("test", "--filter", "bogus")
        self.assertEqual(code, 3)

    def test_report_formats_output_dir_and_seed(self) -> None:
        self.init_config()
        code, out, err = self.run_cli(
            "test",
            "--report",
            "junit,json",
            "--output-dir",
            "out",
            "--seed",
            "5",
            "--offline",
        )
        self.assertEqual(code, 1)
        self.assertTrue((self.dir / "out" / "secretsift-report.xml").exists())
        data = json.loads((self.dir / "out" / "secretsift-report.json").read_text())
        self.assertEqual(data["seed"], 5)
        self.assertNotIn("Secretsift report", out)  # terminal not requested

    def test_unknown_report_format_exits_3(self) -> None:
        self.init_config()
        self.assertEqual(self.run_cli("test", "--report", "pdf")[0], 3)

    def test_baseline_regressions(self) -> None:
        self.init_config()
        self.run_cli("test", "--report", "json", "--output-dir", "a", "--filter", "network")
        code, out, _ = self.run_cli(
            "test", "--report", "terminal", "--baseline", "a/secretsift-report.json"
        )
        self.assertEqual(code, 1)
        self.assertIn("regressions vs baseline: 1", out)
        self.assertIn("SS-REG-001", out)
        self.run_cli("test", "--report", "json", "--output-dir", "b")
        code, out, _ = self.run_cli(
            "test", "--report", "terminal", "--baseline", "b/secretsift-report.json"
        )
        self.assertIn("regressions vs baseline: 0", out)

    def test_bad_baseline_exits_3(self) -> None:
        self.init_config()
        (self.dir / "bad.json").write_text("{nope")
        self.assertEqual(self.run_cli("test", "--baseline", "bad.json")[0], 3)

    def test_scenario_errors_only_exit_2(self) -> None:
        cfg = dump_default_config().replace("secretsift.demo:leaky_login", "no_such_mod:fn")
        (self.dir / "secretsift.yaml").write_text(cfg)
        self.assertEqual(self.run_cli("test", "--report", "terminal")[0], 2)

    def test_fail_on_warn(self) -> None:
        cfg = dump_default_config().replace("mode: strict", "mode: warn_only")
        (self.dir / "secretsift.yaml").write_text(cfg)
        self.assertEqual(self.run_cli("test", "--report", "json")[0], 0)
        self.assertEqual(self.run_cli("test", "--report", "json", "--fail-on", "warn")[0], 1)


class ReportAndDiffTests(CliCase):
    def make_json(self, name: str, *extra: str) -> str:
        self.init_config()
        self.run_cli("test", "--report", "json", "--output-dir", name, *extra)
        return f"{name}/secretsift-report.json"

    def test_round_trip_conversion(self) -> None:
        src = self.make_json("a")
        cases = (("html", "<html"), ("junit", "<testsuite"), ("terminal", "leaky-login"))
        for fmt, marker in cases:
            code, out, _ = self.run_cli("report", src, "--format", fmt)
            self.assertEqual(code, 0)
            self.assertIn(marker, out)
        code, out, _ = self.run_cli("report", src, "--format", "json", "--output", "copy.json")
        self.assertEqual(code, 0)
        self.assertEqual(
            json.loads(Path("copy.json").read_text())["$schema"], "secretsift-report/1"
        )
        self.assertEqual(stat.S_IMODE(Path("copy.json").stat().st_mode), 0o600)
        self.assertNotIn("\x1b[", self.run_cli("report", src, "-o", "t.txt")[1])
        self.assertNotIn("\x1b[", Path("t.txt").read_text())

    def test_report_bad_file(self) -> None:
        self.assertEqual(self.run_cli("report", "missing.json")[0], 3)

    def test_diff(self) -> None:
        old = self.make_json("a", "--filter", "network")
        new = self.make_json("b")
        code, out, _ = self.run_cli("diff", old, new, "--no-color")
        self.assertEqual(code, 1)
        self.assertEqual(self.run_cli("diff", new, new)[0], 0)


class DemoAndMiscTests(CliCase):
    def test_demo(self) -> None:
        code, out, _ = self.run_cli("demo")
        self.assertEqual(code, 0)
        for name in ("secretsift-report.json", "secretsift-report.html"):
            self.assertIn(name, out)
            self.assertTrue((self.dir / "secretsift-reports" / name).exists())

    def test_version(self) -> None:
        code, out, _ = self.run_cli("version")
        self.assertEqual((code, out.split()[0]), (0, "secretsift"))
        self.assertEqual(self.run_cli("--version")[0], 0)

    def test_unknown_subcommand_and_none(self) -> None:
        code, _, err = self.run_cli("frobnicate")
        self.assertEqual(code, 3)
        self.assertNotIn("Traceback", err)
        self.assertEqual(self.run_cli()[0], 3)
        self.assertEqual(self.run_cli("test", "--bogus-flag")[0], 3)

    def test_help_exits_0(self) -> None:
        self.assertEqual(self.run_cli("--help")[0], 0)

    def test_doctor_and_providers_never_print_env_values(self) -> None:
        self.init_config()
        env = {"OPENAI_API_KEY": FAKE_KEY, "ANTHROPIC_API_KEY": FAKE_KEY + "b"}
        with mock.patch.dict(os.environ, env):
            for argv in (("doctor",), ("providers",), ("validate",)):
                code, out, err = self.run_cli(*argv)
                self.assertEqual(code, 0, argv)
                self.assertNotIn(FAKE_KEY, out + err)
            _, out, _ = self.run_cli("doctor")
            self.assertIn("OPENAI_API_KEY is set", out)
            self.assertIn("python", out)
            self.assertIn("offline mode is on", out)

    def test_doctor_invalid_config_exits_3(self) -> None:
        (self.dir / "secretsift.yaml").write_text("version: 9\n")
        code, out, _ = self.run_cli("doctor")
        self.assertEqual(code, 3)
        self.assertIn("invalid", out)

    def test_doctor_without_config(self) -> None:
        code, out, _ = self.run_cli("doctor")
        self.assertEqual(code, 0)
        self.assertIn("not found", out)

    def test_providers_lists_config_providers(self) -> None:
        self.init_config()
        _, out, _ = self.run_cli("providers")
        self.assertIn("chat", out)

    def test_unexpected_error_exit_70(self) -> None:
        with mock.patch.dict(cli._COMMANDS, {"version": mock.Mock(side_effect=RuntimeError("x"))}):
            code, _, err = self.run_cli("version")
            self.assertEqual(code, 70)
            self.assertNotIn("Traceback", err)
            with mock.patch.dict(os.environ, {"SECRETSIFT_DEBUG": "1"}):
                with self.assertRaises(RuntimeError):
                    self.run_cli("version")


if __name__ == "__main__":
    unittest.main()
