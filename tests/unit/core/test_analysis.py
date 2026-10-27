from __future__ import annotations

import datetime as dt
import unittest

from secretsift.core.analysis import analyze, category_for, format_finding_id
from secretsift.inspectors import default_inspectors
from secretsift.models import Action, Category, DataType, Destination, Event
from secretsift.policies import PolicyConfig, Rule, compile_policy
from secretsift.synthetic import SecretRegistry, generate_value

NOW = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)


def make_event(dest: Destination, payload: str, n: int = 1, **kw: object) -> Event:
    return Event(
        id=f"ev{n}",
        destination=dest,
        component=str(kw.pop("component", "app")),
        timestamp=NOW,
        payload=payload,
        **kw,  # type: ignore[arg-type]
    )


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.reg = SecretRegistry()
        self.key = generate_value("api_key", DataType.API_KEY, run_id="r1", seed=1)
        self.mail = generate_value("mail", DataType.EMAIL, run_id="r1", seed=1)
        self.reg.register(self.key)
        self.reg.register(self.mail)
        self.inspectors = default_inspectors()

    def evaluator(self, rules: list[Rule] | None = None, **kw: object):  # type: ignore[no-untyped-def]
        cfg = PolicyConfig(rules=rules or [], **kw)  # type: ignore[arg-type]
        return compile_policy(
            cfg, {"api_key", "mail"}, {"api_key": DataType.API_KEY, "mail": DataType.EMAIL}
        )

    def run_analysis(self, events: list[Event], ev=None) -> list:  # type: ignore[no-untyped-def]
        return analyze("s", events, self.reg, self.inspectors, ev or self.evaluator())


class TestAnalyze(Base):
    def test_category_and_id_mapping(self) -> None:
        cases = {
            Destination.APPLICATION_LOGS: ("logging", "LOG"),
            Destination.ERROR_REPORT: ("logging", "LOG"),
            Destination.HTTP_REQUEST: ("network", "NET"),
            Destination.AI_REQUEST: ("ai_context", "CTX"),
            Destination.AI_OUTPUT: ("response", "RSP"),
            Destination.STORAGE: ("storage", "STO"),
        }
        for dest, (cat, code) in cases.items():
            f = self.run_analysis([make_event(dest, f"x {self.key.value} y")])
            self.assertEqual(len(f), 1, dest)
            self.assertEqual(f[0].category.value, cat)
            self.assertEqual(f[0].id, f"SS-{code}-001")
        self.assertIsNone(category_for(Destination.APPROVED_TEST_INPUT))
        self.assertEqual(format_finding_id(Category.REGRESSION, 7), "SS-REG-007")

    def test_sequential_ids_per_category(self) -> None:
        evs = [
            make_event(Destination.APPLICATION_LOGS, self.key.value, 1, component="a"),
            make_event(Destination.APPLICATION_LOGS, self.key.value, 2, component="b"),
            make_event(Destination.HTTP_REQUEST, self.key.value, 3),
        ]
        self.assertEqual(
            [f.id for f in self.run_analysis(evs)], ["SS-LOG-001", "SS-LOG-002", "SS-NET-001"]
        )

    def test_dedup_occurrences(self) -> None:
        evs = [
            make_event(Destination.APPLICATION_LOGS, f"a {self.key.value}", i, location="f.py:1")
            for i in range(3)
        ]
        f = self.run_analysis(evs)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].occurrences, 3)

    def test_distinct_location_component_not_merged(self) -> None:
        evs = [
            make_event(Destination.APPLICATION_LOGS, self.key.value, 1, location="f.py:1"),
            make_event(Destination.APPLICATION_LOGS, self.key.value, 2, location="f.py:2"),
        ]
        self.assertEqual(len(self.run_analysis(evs)), 2)

    def test_repeated_value_in_one_event_counts_once(self) -> None:
        f = self.run_analysis(
            [make_event(Destination.APPLICATION_LOGS, f"{self.key.value} {self.key.value}")]
        )
        self.assertEqual(f[0].occurrences, 1)

    def test_two_values_one_event(self) -> None:
        f = self.run_analysis(
            [make_event(Destination.APPLICATION_LOGS, f"{self.key.value} {self.mail.value}")]
        )
        self.assertEqual({x.value_id for x in f}, {self.key.id, self.mail.id})

    def test_deny_warn_allow(self) -> None:
        ev = self.evaluator(
            [
                Rule(
                    id="R1",
                    data="api_key",
                    destination="application_logs",
                    action=Action.DENY,
                    severity="high",
                    remediation="custom fix",
                ),
                Rule(id="R2", data="api_key", destination="http_request", action=Action.WARN),
                Rule(id="R3", data="api_key", destination="storage", action=Action.ALLOW),
            ]
        )
        evs = [
            make_event(d, self.key.value, i)
            for i, d in enumerate(
                [Destination.APPLICATION_LOGS, Destination.HTTP_REQUEST, Destination.STORAGE]
            )
        ]
        f = self.run_analysis(evs, ev)
        self.assertEqual([x.action for x in f], [Action.DENY, Action.WARN])
        self.assertEqual(f[0].rule_id, "R1")
        self.assertEqual(f[0].severity.value, "high")
        self.assertEqual(f[0].remediation, "custom fix")
        self.assertIn("HTTP", f[1].remediation.upper())

    def test_default_allow_yields_nothing(self) -> None:
        ev = self.evaluator(default_action=Action.ALLOW)
        self.assertEqual(
            self.run_analysis([make_event(Destination.STORAGE, self.key.value)], ev), []
        )

    def test_warn_only_mode(self) -> None:
        f = self.run_analysis(
            [make_event(Destination.STORAGE, self.key.value)], self.evaluator(mode="warn_only")
        )
        self.assertEqual(f[0].action, Action.WARN)

    def test_approved_events(self) -> None:
        evs = [
            make_event(Destination.HTTP_REQUEST, self.key.value, 1, approved=True),
            make_event(Destination.APPROVED_TEST_INPUT, self.key.value, 2),
        ]
        self.assertEqual(self.run_analysis(evs), [])

    def test_unhandled_destination_ignored(self) -> None:
        only_logs = [i for i in self.inspectors if Destination.APPLICATION_LOGS in i.destinations]
        f = analyze(
            "s",
            [make_event(Destination.STORAGE, self.key.value)],
            self.reg,
            only_logs,
            self.evaluator(),
        )
        self.assertEqual(f, [])

    def test_confidence(self) -> None:
        import base64

        enc = base64.b64encode(self.key.value.encode()).decode()
        f = self.run_analysis(
            [
                make_event(Destination.APPLICATION_LOGS, self.key.value, 1),
                make_event(Destination.HTTP_REQUEST, f"d={enc}", 2),
            ]
        )
        self.assertEqual(f[0].confidence, "exact")
        self.assertEqual(f[1].confidence, "normalized")
        self.assertEqual(f[1].variant.value, "base64")

    def test_evidence_never_contains_raw(self) -> None:
        payload = f"token={self.key.value} mail {self.mail.value} api_key={self.key.value}"
        for dest in (Destination.APPLICATION_LOGS, Destination.ERROR_REPORT):
            for f in self.run_analysis([make_event(dest, payload)]):
                dump = f.model_dump_json() + repr(f)
                for raw in (self.key.value, self.mail.value):
                    self.assertNotIn(raw, dump)
                self.assertIn("[REDACTED:", f.evidence)

    def test_deterministic_order(self) -> None:
        evs = [
            make_event(
                Destination.APPLICATION_LOGS,
                f"{self.mail.value} {self.key.value}",
                i,
                component=f"c{i % 2}",
            )
            for i in range(4)
        ]
        a = self.run_analysis(evs)
        b = self.run_analysis(list(evs))
        self.assertEqual([x.model_dump() for x in a], [x.model_dump() for x in b])

    def test_accepts_generator_and_dropped_arg(self) -> None:
        f = analyze(
            "s",
            (e for e in [make_event(Destination.STORAGE, self.key.value)]),
            self.reg,
            self.inspectors,
            self.evaluator(),
            collector_dropped=5,
        )
        self.assertEqual(len(f), 1)


class TestStreaming(Base):
    def test_chunks_dedup_and_aggregate_suppressed(self) -> None:
        evs = [
            make_event(Destination.AI_OUTPUT, f"tok {self.key.value}", 1, component="p"),
            make_event(Destination.AI_OUTPUT, f"again {self.key.value}", 2, component="p"),
            make_event(
                Destination.AI_OUTPUT,
                f"tok {self.key.value} again",
                3,
                component="p",
                metadata={"aggregated": True},
            ),
        ]
        f = self.run_analysis(evs)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].occurrences, 2)

    def test_aggregate_first_in_input_still_suppressed(self) -> None:
        evs = [
            make_event(
                Destination.AI_OUTPUT,
                self.key.value,
                1,
                component="p",
                metadata={"aggregated": True},
            ),
            make_event(Destination.AI_OUTPUT, self.key.value, 2, component="p"),
        ]
        f = self.run_analysis(evs)
        self.assertEqual((len(f), f[0].event_id), (1, "ev2"))

    def test_aggregate_only_split_secret_is_found(self) -> None:
        half = len(self.key.value) // 2
        evs = [
            make_event(Destination.AI_OUTPUT, self.key.value[:half], 1, component="p"),
            make_event(Destination.AI_OUTPUT, self.key.value[half:], 2, component="p"),
            make_event(
                Destination.AI_OUTPUT,
                self.key.value,
                3,
                component="p",
                metadata={"aggregated": True},
            ),
        ]
        f = self.run_analysis(evs)
        self.assertEqual([x.event_id for x in f], ["ev3"])

    def test_aggregate_other_component_kept(self) -> None:
        evs = [
            make_event(Destination.AI_OUTPUT, self.key.value, 1, component="p"),
            make_event(
                Destination.AI_OUTPUT,
                self.key.value,
                2,
                component="q",
                metadata={"aggregated": True},
            ),
        ]
        self.assertEqual(len(self.run_analysis(evs)), 2)


if __name__ == "__main__":
    unittest.main()
