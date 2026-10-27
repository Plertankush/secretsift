"""Plugin tests. The fixture logic runs against a minimal fake ``pytest`` module so it is
checked even where pytest is not installed; a real-pytest run is added when available."""

from __future__ import annotations

import importlib.util
import logging
import os
import subprocess
import sys
import tempfile
import textwrap
import types
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

PLUGIN = Path(__file__).resolve().parents[3] / "src/secretsift/integrations/pytest_plugin.py"
HAS_PYTEST = importlib.util.find_spec("pytest") is not None
_log = logging.getLogger("tests.plugin")


class _Failed(Exception):
    pass


def _fake_pytest() -> types.ModuleType:
    mod = types.ModuleType("pytest")

    def fail(msg: str, pytrace: bool = True) -> None:
        raise _Failed(msg)

    mod.fixture = lambda fn: fn  # type: ignore[attr-defined]
    mod.fail = fail  # type: ignore[attr-defined]
    for name in ("Config", "FixtureRequest"):
        setattr(mod, name, object)
    return mod


def _load() -> types.ModuleType:
    with mock.patch.dict(sys.modules, {"pytest": _fake_pytest()}):
        spec = importlib.util.spec_from_file_location("_ld_plugin_under_test", PLUGIN)
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    return mod


class _Node:
    def __init__(self, name: str, marked: bool) -> None:
        self.name = name
        self._marked = marked

    def get_closest_marker(self, name: str) -> object | None:
        return object() if self._marked and name == "secretsift_allow_findings" else None


class _Request:
    def __init__(self, name: str = "test_x[a/b]", marked: bool = False) -> None:
        self.node = _Node(name, marked)


class FixtureLogicTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plugin = _load()

    def run_fixture(self, leak: bool, marked: bool) -> Any:
        gen = self.plugin.secretsift(_Request(marked=marked))
        with mock.patch.dict(sys.modules, {"pytest": _fake_pytest()}):
            drill = next(gen)
            key = drill.secret("tok")
            _log.warning("value %s", key if leak else "masked")
            with self.assertRaises(StopIteration):
                next(gen)
            return drill, None

    def test_clean_test_passes(self) -> None:
        drill, _ = self.run_fixture(leak=False, marked=False)
        self.assertFalse(drill.active)

    def test_leak_fails_at_teardown_without_raw_value(self) -> None:
        gen = self.plugin.secretsift(_Request())
        drill = next(gen)
        key = drill.secret("tok")
        _log.warning("value %s", key)
        with self.assertRaises(_Failed) as ctx:
            next(gen)
        self.assertIn("privacy finding", str(ctx.exception))
        self.assertNotIn(key, str(ctx.exception))
        self.assertFalse(drill.active)

    def test_marker_allows_findings(self) -> None:
        drill, _ = self.run_fixture(leak=True, marked=True)
        self.assertTrue(drill.findings)

    def test_configure_registers_marker(self) -> None:
        config = mock.Mock()
        self.plugin.pytest_configure(config)
        line = config.addinivalue_line.call_args.args
        self.assertEqual(line[0], "markers")
        self.assertIn("secretsift_allow_findings", line[1])

    def test_scenario_name_is_safe(self) -> None:
        self.assertEqual(self.plugin._scenario_name("test_x[a/b]"), "test_x_a_b_")
        self.assertEqual(self.plugin._scenario_name(""), "drill")
        self.assertEqual(len(self.plugin._scenario_name("a" * 300)), 100)


@unittest.skipUnless(HAS_PYTEST, "pytest is not installed")
class RealPytestTests(unittest.TestCase):
    def test_fixture_under_real_pytest(self) -> None:
        body = textwrap.dedent(
            """
            import logging
            import pytest

            def test_leaks(secretsift):
                logging.getLogger("x").warning("k=%s", secretsift.secret("tok"))

            @pytest.mark.secretsift_allow_findings
            def test_allowed(secretsift):
                logging.getLogger("x").warning("k=%s", secretsift.secret("tok"))

            def test_clean(secretsift):
                secretsift.secret("tok")
            """
        )
        # Autoload is disabled so the plugin is registered exactly once (by -p) whether or not the
        # package is installed; with an installed package the entry point would register it a
        # second time and pytest refuses duplicate registration of the same module.
        env = dict(os.environ, PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "test_sample.py").write_text(body)
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-q",
                    "-rE",
                    "-p",
                    "secretsift.integrations.pytest_plugin",
                    "--strict-markers",
                    "-p",
                    "no:cacheprovider",
                ],
                cwd=tmp,
                capture_output=True,
                text=True,
                timeout=120,
                env=env,
            )
        out = proc.stdout + proc.stderr
        self.assertEqual(proc.returncode, 1, out)
        self.assertRegex(out, r"\b1 error\b")
        errors = [line for line in out.splitlines() if line.startswith("ERROR ")]
        self.assertEqual(len(errors), 1, out)
        self.assertIn("test_leaks", errors[0])


if __name__ == "__main__":
    unittest.main()
