from __future__ import annotations

import datetime as dt
import unittest

from secretsift.assertions import (
    BaselineDiff,
    assert_no_findings,
    compare_to_baseline,
    regression_findings,
)
from secretsift.core.analysis import analyze
from secretsift.inspectors import default_inspectors
from secretsift.models import (
    Action,
    Category,
    Coverage,
    DataType,
    Destination,
    Event,
    Finding,
    Report,
    RunSummary,
    ScenarioResult,
    ScenarioStatus,
)
from secretsift.policies import PolicyConfig, compile_policy
from secretsift.synthetic import SecretRegistry, generate_value

NOW = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)


def findings_for(run_id: str, dests: list[tuple[Destination, str]]) -> tuple[list[Finding], str]:
    reg = SecretRegistry()
    val = generate_value("k", DataType.API_KEY, run_id=run_id, seed=None)
    reg.register(val)
    ev = compile_policy(PolicyConfig(), {"k"}, {"k": DataType.API_KEY})
    events = [
        Event(id=f"e{i}", destination=d, component=c, timestamp=NOW, payload=val.value)
        for i, (d, c) in enumerate(dests)
    ]
    return analyze("s", events, reg, default_inspectors(), ev), val.value


def report(findings: list[Finding]) -> Report:
    res = ScenarioResult(
        name="s", category=Category.LOGGING, status=ScenarioStatus.FAILED, findings=findings
    )
    return Report(
        run_id="r",
        tool_version="0",
        started_at=NOW,
        finished_at=NOW,
        seed=None,
        config_path=None,
        summary=RunSummary(
            total=1, passed=0, failed=1, warned=0, errored=0, skipped=0, findings=len(findings)
        ),
        results=[res],
        coverage=Coverage(
            inspectors_active=[], destinations_observed=[], offline=True, limitations=[]
        ),
    )


class TestAssertNoFindings(unittest.TestCase):
    def test_empty_passes(self) -> None:
        assert_no_findings([])

    def test_raises_redacted(self) -> None:
        fs, raw = findings_for("r1", [(Destination.APPLICATION_LOGS, "app")])
        with self.assertRaises(AssertionError) as cm:
            assert_no_findings(fs)
        msg = str(cm.exception)
        self.assertIn("SS-LOG-001", msg)
        self.assertIn("\n", msg)
        self.assertNotIn(raw, msg)

    def test_allow_warn(self) -> None:
        fs, _ = findings_for("r1", [(Destination.APPLICATION_LOGS, "app")])
        warn = [f.model_copy(update={"action": Action.WARN}) for f in fs]
        assert_no_findings(warn, allow_warn=True)
        with self.assertRaises(AssertionError):
            assert_no_findings(warn)
        with self.assertRaises(AssertionError):
            assert_no_findings(fs + warn, allow_warn=True)


class TestBaseline(unittest.TestCase):
    def test_identity_ignores_value_id(self) -> None:
        old, _ = findings_for("run-a", [(Destination.APPLICATION_LOGS, "app")])
        new, _ = findings_for("run-b", [(Destination.APPLICATION_LOGS, "app")])
        self.assertNotEqual(old[0].value_id, new[0].value_id)
        diff = compare_to_baseline(report(old), report(new))
        self.assertEqual((diff.new, diff.fixed, len(diff.unchanged)), ([], [], 1))

    def test_new_fixed_unchanged(self) -> None:
        old, _ = findings_for(
            "a", [(Destination.APPLICATION_LOGS, "app"), (Destination.STORAGE, "fs")]
        )
        new, _ = findings_for(
            "b", [(Destination.APPLICATION_LOGS, "app"), (Destination.HTTP_REQUEST, "httpx")]
        )
        diff = compare_to_baseline(report(old), report(new))
        self.assertEqual([f.destination for f in diff.new], [Destination.HTTP_REQUEST])
        self.assertEqual([f.destination for f in diff.fixed], [Destination.STORAGE])
        self.assertEqual([f.destination for f in diff.unchanged], [Destination.APPLICATION_LOGS])

    def test_component_change_is_new_and_fixed(self) -> None:
        old, _ = findings_for("a", [(Destination.APPLICATION_LOGS, "x")])
        new, _ = findings_for("b", [(Destination.APPLICATION_LOGS, "y")])
        diff = compare_to_baseline(report(old), report(new))
        self.assertEqual((len(diff.new), len(diff.fixed), len(diff.unchanged)), (1, 1, 0))

    def test_regression_findings(self) -> None:
        new, raw = findings_for(
            "b", [(Destination.APPLICATION_LOGS, "a"), (Destination.STORAGE, "b")]
        )
        out = regression_findings(compare_to_baseline(report([]), report(new)))
        self.assertEqual([f.id for f in out], ["SS-REG-001", "SS-REG-002"])
        self.assertTrue(all(f.category is Category.REGRESSION for f in out))
        self.assertNotIn(raw, "".join(f.model_dump_json() for f in out))
        self.assertEqual(regression_findings(BaselineDiff()), [])


if __name__ == "__main__":
    unittest.main()
