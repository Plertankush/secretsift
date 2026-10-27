"""Generator, markers and fixtures."""

from __future__ import annotations

import re
import threading
import unittest

from secretsift.exceptions import ConfigError
from secretsift.models import DataType
from secretsift.synthetic import generate_set, generate_value
from secretsift.synthetic.markers import derive_root, make_marker, stream_bytes


class GeneratorTests(unittest.TestCase):
    def test_every_type_has_marker_length_and_id(self) -> None:
        for dt in DataType:
            v = generate_value("lbl", dt, run_id="r1", seed=1)
            self.assertGreaterEqual(len(v.marker), 8, dt)
            self.assertGreaterEqual(len(v.value), 12, dt)
            self.assertIn(v.marker, v.value, dt)
            self.assertRegex(v.id, r"^sv_[0-9a-f]{8}$")
            self.assertEqual(v.data_type, dt)

    def test_formats(self) -> None:
        g = lambda t: generate_value("x", t, run_id="r", seed=3).value  # noqa: E731
        self.assertTrue(g(DataType.API_KEY).startswith("sk-test-"))
        parts = g(DataType.BEARER_TOKEN).split(".")
        self.assertEqual(len(parts), 3)
        self.assertTrue(parts[0].startswith("eyJ"))
        self.assertRegex(g(DataType.SESSION_ID), r"^[0-9a-f]+$")
        self.assertTrue(g(DataType.EMAIL).endswith("@example.test"))
        self.assertRegex(g(DataType.PHONE), r"^\+1-555-01\d\d-\d{8}$")
        self.assertRegex(g(DataType.CUSTOMER_ID), r"^CUST-[0-9a-f]{12}-\d{4}$")
        self.assertRegex(g(DataType.PASSWORD), r"[!&#]")

    def test_deterministic_with_seed(self) -> None:
        for dt in DataType:
            a = generate_value("k", dt, run_id="r", seed=42)
            b = generate_value("k", dt, run_id="r", seed=42)
            self.assertEqual(a, b)

    def test_differs_by_seed_label_run(self) -> None:
        base = generate_value("k", DataType.API_KEY, run_id="r", seed=1).value
        self.assertNotEqual(base, generate_value("k", DataType.API_KEY, run_id="r", seed=2).value)
        self.assertNotEqual(base, generate_value("k2", DataType.API_KEY, run_id="r", seed=1).value)
        self.assertNotEqual(base, generate_value("k", DataType.API_KEY, run_id="r2", seed=1).value)

    def test_unseeded_is_random(self) -> None:
        a = generate_value("k", DataType.API_KEY, run_id="r", seed=None)
        b = generate_value("k", DataType.API_KEY, run_id="r", seed=None)
        self.assertNotEqual(a.value, b.value)
        self.assertNotEqual(a.marker, b.marker)

    def test_seed_zero_is_deterministic_not_random(self) -> None:
        a = generate_value("k", DataType.NAME, run_id="r", seed=0)
        self.assertEqual(a, generate_value("k", DataType.NAME, run_id="r", seed=0))

    def test_markers_unique_across_labels(self) -> None:
        markers = {
            generate_value(f"label{i}", dt, run_id="r", seed=5).marker
            for i in range(200)
            for dt in (DataType.API_KEY, DataType.PHONE)
        }
        self.assertEqual(len(markers), 400)

    def test_no_global_random_state_used(self) -> None:
        import random

        random.seed(1)
        before = random.random()
        random.seed(1)
        generate_value("k", DataType.API_KEY, run_id="r", seed=9)
        self.assertEqual(before, random.random())

    def test_repr_and_dump_hide_value(self) -> None:
        v = generate_value("k", DataType.API_KEY, run_id="r", seed=1)
        self.assertNotIn(v.value, repr(v))
        self.assertNotIn(v.value, str(v.model_dump()))
        self.assertNotIn(v.value, v.model_dump_json())

    def test_invalid_inputs(self) -> None:
        with self.assertRaises(ConfigError):
            generate_value("", DataType.API_KEY, run_id="r", seed=1)
        with self.assertRaises(ConfigError):
            generate_value("k", DataType.API_KEY, run_id="", seed=1)
        with self.assertRaises(ConfigError):
            generate_value("k", "nope", run_id="r", seed=1)  # type: ignore[arg-type]

    def test_string_type_is_coerced(self) -> None:
        v = generate_value("k", "synthetic_email", run_id="r", seed=1)  # type: ignore[arg-type]
        self.assertEqual(v.data_type, DataType.EMAIL)

    def test_thread_safety(self) -> None:
        out: list[str] = []

        def work() -> None:
            out.append(generate_value("k", DataType.API_KEY, run_id="r", seed=11).value)

        threads = [threading.Thread(target=work) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(set(out)), 1)


class MarkerTests(unittest.TestCase):
    def test_stream_bytes_length_and_determinism(self) -> None:
        root = derive_root(1, "r", "l")
        self.assertEqual(len(stream_bytes(root, "p", 100)), 100)
        self.assertEqual(stream_bytes(root, "p", 40), stream_bytes(root, "p", 100)[:40])
        self.assertNotEqual(stream_bytes(root, "p", 8), stream_bytes(root, "q", 8))

    def test_marker_shapes(self) -> None:
        root = derive_root(1, "r", "l")
        self.assertRegex(make_marker(root, DataType.API_KEY), r"^[0-9a-f]{12}$")
        self.assertRegex(make_marker(root, DataType.PHONE), r"^\d{8}$")


class FixturesTests(unittest.TestCase):
    def test_generate_set(self) -> None:
        vs = generate_set([("a", DataType.API_KEY), ("b", DataType.EMAIL)], "run", 1)
        self.assertEqual([v.label for v in vs], ["a", "b"])
        again = generate_set([("a", DataType.API_KEY), ("b", DataType.EMAIL)], "run", 1)
        self.assertEqual(vs, again)
        self.assertEqual(len({v.id for v in vs}), 2)

    def test_duplicate_label_rejected(self) -> None:
        with self.assertRaises(ConfigError):
            generate_set([("a", DataType.API_KEY), ("a", DataType.EMAIL)], "run", 1)

    def test_empty(self) -> None:
        self.assertEqual(generate_set([], "run", 1), [])
        self.assertIsNone(re.match("x", "y"))
