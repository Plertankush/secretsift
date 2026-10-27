"""Policy compilation and evaluation tests."""

from __future__ import annotations

import datetime as dt
import unittest

from secretsift.exceptions import PolicyError
from secretsift.models import Action, DataType, Destination, Event, Severity, SyntheticValue
from secretsift.policies import PolicyConfig, compile_policy, remediation_for
from secretsift.synthetic import SecretRegistry, generate_value

LABELS = {"key": DataType.API_KEY, "mail": DataType.EMAIL}


def ev(dest: Destination, approved: bool = False) -> Event:
    return Event(
        id="e1",
        destination=dest,
        component="c",
        timestamp=dt.datetime(2026, 1, 1),
        payload="x",
        approved=approved,
    )


def pol(rules: list[dict[str, object]], **kw: object) -> PolicyConfig:
    return PolicyConfig.model_validate({"rules": rules, **kw})


def val(label: str = "key", seed: int = 1) -> SyntheticValue:
    return generate_value(label, LABELS[label], run_id="r1", seed=seed)


def build(rules: list[dict[str, object]], **kw: object):  # type: ignore[no-untyped-def]
    return compile_policy(pol(rules, **kw), set(LABELS), LABELS)


class PrecedenceTests(unittest.TestCase):
    def test_default_action(self) -> None:
        d = build([]).decide("s", val(), ev(Destination.APPLICATION_LOGS))
        self.assertEqual((d.action, d.rule_id, d.severity), (Action.DENY, None, Severity.MEDIUM))
        d = build([], default_action="warn").decide("s", val(), ev(Destination.STORAGE))
        self.assertEqual((d.action, d.severity), (Action.WARN, Severity.LOW))
        d = build([], default_action="allow").decide("s", val(), ev(Destination.STORAGE))
        self.assertEqual(d.action, Action.ALLOW)

    def test_label_beats_type_beats_wildcard(self) -> None:
        ev_ = build(
            [
                {"id": "W", "data": "*", "action": "allow"},
                {"id": "T", "data": "synthetic_api_key", "action": "warn"},
                {"id": "L", "data": "key", "action": "deny"},
            ]
        )
        e = ev(Destination.APPLICATION_LOGS)
        self.assertEqual(ev_.decide("s", val(), e).rule_id, "L")
        only = build(
            [
                {"id": "W", "data": "*", "action": "allow"},
                {"id": "T", "data": "synthetic_api_key", "action": "warn"},
            ]
        )
        self.assertEqual(only.decide("s", val(), e).rule_id, "T")
        self.assertEqual(only.decide("s", val("mail"), e).rule_id, "W")

    def test_destination_exact_beats_wildcard(self) -> None:
        p = build(
            [
                {"id": "A", "data": "key", "action": "allow"},
                {"id": "B", "data": "key", "destination": "application_logs", "action": "deny"},
            ]
        )
        self.assertEqual(p.decide("s", val(), ev(Destination.APPLICATION_LOGS)).rule_id, "B")
        self.assertEqual(p.decide("s", val(), ev(Destination.STORAGE)).rule_id, "A")

    def test_scenario_scoped_beats_unscoped(self) -> None:
        p = build(
            [
                {"id": "U", "data": "key", "destination": "application_logs", "action": "deny"},
                {"id": "S", "data": "*", "scenario": "s1", "action": "allow"},
            ]
        )
        e = ev(Destination.APPLICATION_LOGS)
        self.assertEqual(p.decide("s1", val(), e).rule_id, "S")
        self.assertEqual(p.decide("s2", val(), e).rule_id, "U")

    def test_severity_override_and_reason(self) -> None:
        p = build(
            [{"id": "R", "data": "key", "action": "deny", "severity": "HIGH", "reason": "no"}]
        )
        d = p.decide("s", val(), ev(Destination.STORAGE))
        self.assertEqual((d.severity, d.reason), (Severity.HIGH, "no"))
        p = build([{"id": "R", "data": "key", "action": "warn"}])
        self.assertEqual(p.decide("s", val(), ev(Destination.STORAGE)).severity, Severity.LOW)

    def test_warn_only_downgrade(self) -> None:
        p = build([{"id": "R", "data": "key", "action": "deny"}], mode="warn_only")
        d = p.decide("s", val(), ev(Destination.STORAGE))
        self.assertEqual((d.action, d.rule_id, d.severity), (Action.WARN, "R", Severity.LOW))
        self.assertEqual(
            build([], mode="warn_only").decide("s", val(), ev(Destination.STORAGE)).action,
            Action.WARN,
        )


class ApprovalTests(unittest.TestCase):
    def test_approved_always_allow(self) -> None:
        p = build([{"id": "R", "data": "*", "action": "deny"}])
        d = p.decide("s", val(), ev(Destination.HTTP_REQUEST, approved=True))
        self.assertEqual((d.action, d.rule_id), (Action.ALLOW, None))
        d = p.decide("s", val(), ev(Destination.APPROVED_TEST_INPUT))
        self.assertEqual(d.action, Action.ALLOW)
        self.assertIn("approved", d.reason)

    def test_scenario_approved_destinations(self) -> None:
        p = compile_policy(
            pol([]),
            set(LABELS),
            LABELS,
            scenario_names=["a", "b"],
            approved_destinations={"a": [Destination.HTTP_REQUEST]},
        )
        e = ev(Destination.HTTP_REQUEST)
        self.assertEqual(p.decide("a", val(), e).action, Action.ALLOW)
        self.assertEqual(p.decide("b", val(), e).action, Action.DENY)

    def test_approved_destinations_unknown_scenario(self) -> None:
        with self.assertRaisesRegex(PolicyError, "unknown scenario 'zz'"):
            compile_policy(
                pol([]),
                set(LABELS),
                LABELS,
                scenario_names=["a"],
                approved_destinations={"zz": [Destination.STORAGE]},
            )


class ValidationTests(unittest.TestCase):
    def check(self, rules: list[dict[str, object]], pattern: str, **kw: object) -> None:
        with self.assertRaisesRegex(PolicyError, pattern):
            compile_policy(pol(rules), set(LABELS), LABELS, **kw)  # type: ignore[arg-type]

    def test_unknown_destination(self) -> None:
        self.check(
            [{"id": "R", "destination": "nowhere", "action": "deny"}],
            "unknown destination 'nowhere'",
        )

    def test_unknown_label(self) -> None:
        self.check([{"id": "R", "data": "ghost", "action": "deny"}], "unknown data 'ghost'")

    def test_unknown_scenario(self) -> None:
        self.check(
            [{"id": "R", "scenario": "nope", "action": "deny"}],
            "unknown scenario 'nope'",
            scenario_names=["a"],
        )

    def test_scenario_not_checked_without_names(self) -> None:
        self.assertIsNotNone(build([{"id": "R", "scenario": "any", "action": "deny"}]))

    def test_invalid_severity(self) -> None:
        self.check([{"id": "R", "action": "deny", "severity": "huge"}], "invalid severity 'huge'")

    def test_duplicate_ids(self) -> None:
        self.check(
            [{"id": "R", "action": "deny"}, {"id": "R", "data": "key", "action": "warn"}],
            "duplicate rule id 'R'",
        )

    def test_conflict(self) -> None:
        self.check(
            [
                {"id": "A", "data": "key", "action": "deny"},
                {"id": "B", "data": "key", "action": "allow"},
            ],
            "conflict",
        )

    def test_same_action_not_conflict(self) -> None:
        build(
            [
                {"id": "A", "data": "key", "action": "deny"},
                {"id": "B", "data": "key", "action": "deny"},
            ]
        )

    def test_different_scope_not_conflict(self) -> None:
        build(
            [
                {"id": "A", "data": "key", "action": "deny"},
                {"id": "B", "data": "key", "scenario": "s", "action": "allow"},
            ]
        )

    def test_schema_extra_forbidden(self) -> None:
        with self.assertRaisesRegex(ValueError, "colour"):
            pol([{"id": "R", "action": "deny", "colour": "red"}])

    def test_errors_contain_no_secret(self) -> None:
        v = val()
        try:
            build([{"id": "R", "data": "ghost", "action": "deny"}])
        except PolicyError as exc:
            self.assertNotIn(v.value, str(exc))

    def test_deterministic_decisions(self) -> None:
        rules = [{"id": "R", "data": "key", "destination": "storage", "action": "deny"}]
        a = build(rules).decide("s", val(seed=5), ev(Destination.STORAGE))
        b = build(rules).decide("s", val(seed=5), ev(Destination.STORAGE))
        self.assertEqual(a, b)

    def test_works_with_registry_values(self) -> None:
        reg = SecretRegistry()
        v = val()
        reg.register(v)
        m = reg.find("token " + v.value)[0]
        d = build([]).decide("s", reg.get(m.value_id), ev(Destination.APPLICATION_LOGS))
        self.assertEqual(d.action, Action.DENY)
        self.assertNotIn(v.value, repr(d))


class RulesTests(unittest.TestCase):
    def test_remediation_for_all_destinations(self) -> None:
        for d in Destination:
            self.assertTrue(remediation_for(d))
        self.assertTrue(remediation_for("storage"))
        self.assertTrue(remediation_for("bogus"))

    def test_rule_remediation_lookup(self) -> None:
        p = build([{"id": "R", "data": "key", "action": "deny", "remediation": "fix it"}])
        self.assertEqual(p.remediation_for_rule("R"), "fix it")
        self.assertIsNone(p.remediation_for_rule("nope"))
        self.assertEqual(p.rule_ids, ["R"])


if __name__ == "__main__":
    unittest.main()
