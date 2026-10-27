from __future__ import annotations

import unittest

from secretsift.core.context import RunContext
from secretsift.core.lifecycle import Lifecycle
from secretsift.exceptions import ScenarioError
from secretsift.models import DataType, Destination
from secretsift.synthetic import generate_value


def boom() -> None:
    raise RuntimeError("secret-ish message")


class TestLifecycle(unittest.TestCase):
    def make_ctx(self) -> RunContext:
        ctx = RunContext(scenario="s", run_id="r1", seed=1)
        ctx.add_value(generate_value("k", DataType.API_KEY, run_id="r1", seed=1))
        ctx.collector.record(Destination.STORAGE, "c", "payload")
        return ctx

    def test_context_indexes_values(self) -> None:
        ctx = self.make_ctx()
        self.assertEqual(list(ctx.values), ["k"])
        self.assertEqual(len(ctx.registry.values()), 1)
        self.assertNotIn(ctx.values["k"].value, repr(ctx))

    def test_order_lifo_then_context(self) -> None:
        order: list[str] = []
        ctx = self.make_ctx()
        with Lifecycle(ctx) as lc:
            lc.add("a", lambda: order.append("a"))
            lc.add("b", lambda: order.append("b"))
            lc.add("peek", lambda: order.append(f"reg={len(ctx.registry.values())}"))
        self.assertEqual(order, ["reg=1", "b", "a"])
        self.assertEqual(len(ctx.registry.values()), 0)
        self.assertEqual(len(ctx.collector), 0)

    def test_cleanup_on_exception_propagates_original(self) -> None:
        ctx = self.make_ctx()
        with self.assertRaises(ValueError):
            with Lifecycle(ctx):
                raise ValueError("body")
        self.assertEqual(len(ctx.registry.values()), 0)
        self.assertEqual(len(ctx.collector), 0)

    def test_failing_step_does_not_skip_others(self) -> None:
        ran: list[str] = []
        ctx = self.make_ctx()
        with self.assertRaises(ScenarioError) as cm:
            with Lifecycle(ctx) as lc:
                lc.add("first", lambda: ran.append("first"))
                lc.add("bad", boom)
                lc.add("last", lambda: ran.append("last"))
        self.assertEqual(ran, ["last", "first"])
        self.assertIn("bad (RuntimeError)", str(cm.exception))
        self.assertNotIn("secret-ish", str(cm.exception))
        self.assertEqual(len(ctx.registry.values()), 0)

    def test_failing_step_with_body_exception_keeps_body_exception(self) -> None:
        ctx = self.make_ctx()
        lc = Lifecycle(ctx)
        with self.assertRaises(KeyError):
            with lc:
                lc.add("bad", boom)
                raise KeyError("x")
        self.assertEqual(lc.failed_steps, ["bad"])
        self.assertEqual(len(ctx.registry.values()), 0)

    def test_without_context(self) -> None:
        ran: list[int] = []
        with Lifecycle() as lc:
            lc.add("x", lambda: ran.append(1))
        self.assertEqual(ran, [1])
        self.assertEqual(lc.completed_steps, ["x"])


if __name__ == "__main__":
    unittest.main()
