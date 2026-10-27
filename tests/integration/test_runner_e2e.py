"""End-to-end tests: YAML config -> run_config -> Report, against real instrumentation."""

from __future__ import annotations

import contextlib
import http.server
import io
import logging
import sys
import tempfile
import textwrap
import threading
import unittest
from pathlib import Path

import yaml

from secretsift.config import dump_default_config, parse_config
from secretsift.core.runner import run_config
from secretsift.models import Category, Destination, Report, ScenarioStatus

TARGETS = """
import json, logging, urllib.request

def boom(api_key, note):
    raise RuntimeError("failed for " + api_key)

def fetch(api_key, url):
    urllib.request.urlopen(url, timeout=2).read()

def chat_stream(provider, api_key, note):
    from secretsift.providers.base import Message, ProviderRequest
    req = ProviderRequest(messages=[Message(role="user", content=api_key)])
    return "".join(provider.stream(req))

def chat_complete(provider, api_key, note):
    from secretsift.providers.base import Message, ProviderRequest
    return provider.complete(ProviderRequest(messages=[Message(role="user", content=api_key)]))

def writes_file(api_key, path):
    with open(path, "w") as fh:
        fh.write("key=" + api_key)
"""

BASE = {
    "version": 1,
    "seed": 7,
    "synthetic": {"values": [{"label": "k", "type": "synthetic_api_key"}]},
    "providers": {
        "echo": {"type": "mock", "behavior": "echo", "chunk_size": 3},
        "leak": {"type": "mock", "behavior": "leaky_error"},
        "safe": {"type": "mock", "behavior": "safe"},
    },
}


def scen(name: str, category: str, target: str, **kw: object) -> dict[str, object]:
    out: dict[str, object] = {
        "name": name,
        "category": category,
        "target": target,
        "inputs": {"api_key": "{{ k }}", "note": "hi"},
    }
    out.update(kw)
    return out


class RunnerE2E(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        self.mod = f"lk_targets_{id(self):x}"
        (self.dir / f"{self.mod}.py").write_text(textwrap.dedent(TARGETS))
        self.addCleanup(sys.modules.pop, self.mod, None)

    def run_cfg(self, scenarios: list[dict[str, object]], **top: object) -> Report:
        data = {**BASE, "sys_path": [str(self.dir)], "scenarios": scenarios, **top}
        path = self.dir / "secretsift.yaml"
        path.write_text(yaml.safe_dump(data))
        return run_config(parse_config(yaml.safe_load(path.read_text())), config_path=path)

    def t(self, fn: str) -> str:
        return f"{self.mod}:{fn}"

    def test_demo_leaky_fails_safe_passes(self) -> None:
        rep = self.run_cfg(
            [
                scen("leaky", "logging", "secretsift.demo:leaky_login"),
                scen("safe", "logging", "secretsift.demo:safe_login"),
                scen("leaky-chat", "ai_context", "secretsift.demo:safe_chat", provider="safe"),
            ]
        )
        by = {r.name: r for r in rep.results}
        self.assertEqual(by["leaky"].status, ScenarioStatus.FAILED)
        f = by["leaky"].findings[0]
        self.assertEqual(
            (f.category, f.destination), (Category.LOGGING, Destination.APPLICATION_LOGS)
        )
        self.assertEqual(by["safe"].status, ScenarioStatus.PASSED)
        self.assertEqual(by["leaky-chat"].status, ScenarioStatus.PASSED)
        self.assertEqual(rep.exit_code, 1)
        self.assertEqual((rep.summary.passed, rep.summary.failed, rep.summary.findings), (2, 1, 1))
        self.assertEqual(rep.seed, 7)
        self.assertTrue(rep.coverage.offline)
        self.assertIn("logs", rep.coverage.inspectors_active)
        self.assertTrue(any("subprocess" in s for s in rep.coverage.limitations))

    def test_leaky_chat_detected_in_request_and_secret_never_in_report(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rep = self.run_cfg(
                [scen("c", "ai_context", "secretsift.demo:leaky_chat", provider="safe")]
            )
        res = rep.results[0]
        self.assertEqual(res.status, ScenarioStatus.FAILED)
        dests = {f.destination for f in res.findings}
        self.assertIn(Destination.AI_REQUEST, dests)
        self.assertIn(Destination.APPLICATION_LOGS, dests)  # printed to stdout
        self.assertTrue(all("[REDACTED:" in f.evidence for f in res.findings))
        self._assert_no_secret(rep.model_dump_json())

    def _assert_no_secret(self, text: str) -> None:
        self.assertNotIn("sk-test-", text)

    def test_runner_output_has_no_secret(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rep = self.run_cfg([scen("l", "logging", "secretsift.demo:leaky_login")])
        self.assertEqual(rep.results[0].status, ScenarioStatus.FAILED)
        self.assertNotIn("sk-test-", out.getvalue() + err.getvalue())
        self.assertIn("[REDACTED:", rep.results[0].findings[0].evidence)
        self._assert_no_secret(repr(rep) + rep.model_dump_json())

    def test_raising_target_is_errored_not_crash(self) -> None:
        rep = self.run_cfg(
            [
                scen("b", "logging", self.t("boom")),
                scen("ok", "logging", "secretsift.demo:safe_login"),
            ]
        )
        r = rep.results[0]
        # the exception message contains the key, so the error_report leak is a finding
        self.assertEqual(r.status, ScenarioStatus.FAILED)
        self.assertIn(Destination.ERROR_REPORT, {f.destination for f in r.findings})
        self.assertEqual(rep.results[1].status, ScenarioStatus.PASSED)
        self._assert_no_secret(rep.model_dump_json())

    def test_raising_target_without_leak_is_errored(self) -> None:
        (self.dir / f"{self.mod}.py").write_text(TARGETS + "\ndef bad(api_key, note):\n    1/0\n")
        rep = self.run_cfg([scen("b", "logging", self.t("bad"))])
        r = rep.results[0]
        self.assertEqual(r.status, ScenarioStatus.ERRORED)
        self.assertIn("ZeroDivisionError", r.error or "")
        self.assertEqual(rep.exit_code, 2)

    def test_import_failure_is_errored(self) -> None:
        rep = self.run_cfg([scen("m", "logging", "no_such_module_xyz:fn")])
        self.assertEqual(rep.results[0].status, ScenarioStatus.ERRORED)

    def test_expect_exception_passes(self) -> None:
        (self.dir / f"{self.mod}.py").write_text(TARGETS + "\ndef bad(api_key, note):\n    1/0\n")
        rep = self.run_cfg([scen("b", "logging", self.t("bad"), expect_exception=True)])
        self.assertEqual(rep.results[0].status, ScenarioStatus.PASSED)

    def test_state_restored_and_cleaned(self) -> None:
        from secretsift.core import runner

        path_before = list(sys.path)
        stdout, stderr = sys.stdout, sys.stderr
        handlers = list(logging.getLogger().handlers)
        level = logging.getLogger().level
        captured: list[object] = []
        orig = runner.RunContext

        def spy(**kw: object) -> object:
            ctx = orig(**kw)  # type: ignore[arg-type]
            captured.append(ctx)
            return ctx

        runner.RunContext = spy  # type: ignore[assignment]
        try:
            self.run_cfg(
                [
                    scen("l", "logging", "secretsift.demo:leaky_login"),
                    scen("b", "logging", self.t("boom")),
                ]
            )
        finally:
            runner.RunContext = orig  # type: ignore[misc]
        self.assertEqual(sys.path, path_before)
        self.assertIs(sys.stdout, stdout)
        self.assertIs(sys.stderr, stderr)
        self.assertEqual(logging.getLogger().handlers, handlers)
        self.assertEqual(logging.getLogger().level, level)
        self.assertEqual(len(captured), 2)
        for ctx in captured:
            self.assertEqual(len(ctx.registry.values()), 0)  # type: ignore[attr-defined]
            self.assertEqual(len(ctx.collector), 0)  # type: ignore[attr-defined]

    def test_same_seed_same_decisions(self) -> None:
        sc = [
            scen("l", "logging", "secretsift.demo:leaky_login"),
            scen("c", "ai_context", "secretsift.demo:leaky_chat", provider="safe"),
        ]
        with contextlib.redirect_stdout(io.StringIO()):
            a, b = self.run_cfg(sc), self.run_cfg(sc)

        def key(r: Report) -> list[tuple[object, ...]]:
            return [
                (
                    x.name,
                    x.status,
                    [
                        (f.id, f.rule_id, f.action, f.destination, f.component, f.severity)
                        for f in x.findings
                    ],
                )
                for x in r.results
            ]

        self.assertEqual(key(a), key(b))
        self.assertNotEqual(a.run_id, b.run_id)

    def test_offline_loopback_allowed_and_external_blocked(self) -> None:
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *a: object) -> None:
                return

        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        url = f"http://127.0.0.1:{srv.server_address[1]}/"
        rep = self.run_cfg(
            [
                {
                    "name": "loop",
                    "category": "network",
                    "target": self.t("fetch"),
                    "inputs": {"api_key": "{{ k }}", "url": url},
                },
                {
                    "name": "ext",
                    "category": "network",
                    "target": self.t("fetch"),
                    "inputs": {"api_key": "{{ k }}", "url": "http://203.0.113.9/x"},
                },
            ]
        )
        loop, ext = rep.results
        self.assertEqual(loop.status, ScenarioStatus.PASSED)
        self.assertEqual(ext.status, ScenarioStatus.ERRORED)
        self.assertIn("OfflineViolationError", ext.error or "")

    def test_streaming_secret_split_across_chunks_single_response_finding(self) -> None:
        rep = self.run_cfg([scen("s", "response", self.t("chat_stream"), provider="echo")])
        res = rep.results[0]
        rsp = [f for f in res.findings if f.category is Category.RESPONSE]
        self.assertEqual(len(rsp), 1)
        self.assertEqual(res.status, ScenarioStatus.FAILED)

    def test_leaky_error_provider_detected(self) -> None:
        rep = self.run_cfg([scen("e", "ai_context", self.t("chat_complete"), provider="leak")])
        res = rep.results[0]
        self.assertIn(Destination.ERROR_REPORT, {f.destination for f in res.findings})
        self.assertEqual(res.status, ScenarioStatus.FAILED)

    def test_storage_scan(self) -> None:
        target = self.dir / "out.txt"
        rep = self.run_cfg(
            [
                {
                    "name": "st",
                    "category": "storage",
                    "target": self.t("writes_file"),
                    "inputs": {"api_key": "{{ k }}", "path": str(target)},
                    "storage_paths": [str(target)],
                }
            ]
        )
        res = rep.results[0]
        self.assertEqual(res.status, ScenarioStatus.FAILED)
        self.assertEqual({f.category for f in res.findings}, {Category.STORAGE})

    def test_starter_config_runs(self) -> None:
        rep = run_config(parse_config(yaml.safe_load(dump_default_config())))
        by = {r.name: r.status for r in rep.results}
        self.assertEqual(
            by, {"leaky-login": ScenarioStatus.FAILED, "safe-login": ScenarioStatus.PASSED}
        )
        self.assertIsNone(rep.config_path)

    def test_category_filter(self) -> None:
        cfg = parse_config(
            {
                **BASE,
                "scenarios": [
                    scen("l", "logging", "secretsift.demo:leaky_login"),
                    scen("c", "ai_context", "secretsift.demo:safe_chat", provider="safe"),
                ],
            }
        )
        rep = run_config(cfg, category_filter="logging")
        self.assertEqual(
            [r.status for r in rep.results], [ScenarioStatus.FAILED, ScenarioStatus.SKIPPED]
        )
        self.assertIn("filter", rep.results[1].skipped_reason or "")
        self.assertEqual(rep.summary.skipped, 1)

    def test_offline_override(self) -> None:
        cfg = parse_config(
            {**BASE, "scenarios": [scen("l", "logging", "secretsift.demo:safe_login")]}
        )
        self.assertFalse(run_config(cfg, offline_override=False).coverage.offline)
        self.assertTrue(run_config(cfg).coverage.offline)


if __name__ == "__main__":
    unittest.main()
