"""Security properties: values never leak through evidence, repr, errors or redaction."""

from __future__ import annotations

import base64
import datetime as dt
import json
import random
import unittest
from urllib.parse import quote, quote_plus

from secretsift.evidence import build_evidence
from secretsift.models import DataType, Destination, Event
from secretsift.synthetic import SecretRegistry, generate_set

TYPES = [(t.value, t) for t in DataType]
VALUES = generate_set(TYPES, "sec-run", 99)


def registry() -> SecretRegistry:
    r = SecretRegistry()
    for v in VALUES:
        r.register(v)
    return r


def encodings(value: str) -> list[str]:
    raw = value.encode()
    forms = [
        value,
        value.upper(),
        quote(value, safe=""),
        quote_plus(value),
        raw.hex(),
        raw.hex().upper(),
        json.dumps(value),
        json.dumps(value)[1:-1],
    ]
    for pad in range(3):
        blob = b"~" * pad + raw
        forms.append(base64.b64encode(blob).decode())
        forms.append(base64.urlsafe_b64encode(blob).decode().rstrip("="))
    forms.append(" ".join(value[i : i + 5] for i in range(0, len(value), 5)))
    return forms


def event(payload: str) -> Event:
    return Event(
        id="ev_sec",
        destination=Destination.APPLICATION_LOGS,
        component="c",
        timestamp=dt.datetime.now(dt.UTC),
        payload=payload,
    )


class RedactionSecurityTests(unittest.TestCase):
    def test_every_value_in_every_encoding_is_detected_and_removed(self) -> None:
        r = registry()
        for v in VALUES:
            for form in encodings(v.value):
                text = f"before {form} after"
                ms = r.find(text)
                self.assertTrue(any(m.value_id == v.id for m in ms), (v.label, form[:20]))
                out = r.redact(text)
                self.assertEqual(r.find(out), [], (v.label, out))
                self.assertEqual(r.redact(out), out)

    def test_evidence_never_leaks_for_any_window_and_position(self) -> None:
        r = registry()
        rng = random.Random(7)
        for v in VALUES:
            for form in encodings(v.value):
                for _ in range(4):
                    left = "L" * rng.randint(0, 90)
                    right = "R" * rng.randint(0, 90)
                    text = left + form + right
                    out = build_evidence(event(text), r.find(text), r, rng.randint(0, 60))
                    self.assertEqual(r.find(out), [], (v.label, out))
                    self.assertNotIn(v.value, out)
                    self.assertLessEqual(len(out), 240)
                    self.assertNotIn(v.marker, out)

    def test_evidence_with_every_value_adjacent(self) -> None:
        r = registry()
        text = "|".join(v.value for v in VALUES)
        out = build_evidence(event(text), r.find(text), r, 40)
        for v in VALUES:
            self.assertNotIn(v.value, out)
            self.assertNotIn(v.marker, out)

    def test_marker_not_in_evidence_even_with_unregistered_context(self) -> None:
        r = registry()
        text = f"ctx {VALUES[0].marker} {VALUES[0].value}"
        out = build_evidence(event(text), r.find(text), r, 40)
        self.assertNotIn(VALUES[0].value, out)

    def test_repr_and_dump_do_not_expose_values(self) -> None:
        r = registry()
        blob = repr(r) + repr(r.values()) + "".join(v.model_dump_json() for v in VALUES)
        for v in VALUES:
            self.assertNotIn(v.value, blob)
        ev = event(VALUES[0].value)
        self.assertNotIn(VALUES[0].value, repr(ev) + ev.model_dump_json())

    def test_get_error_does_not_leak(self) -> None:
        r = registry()
        with self.assertRaises(KeyError) as ctx:
            r.get("sv_00000000")
        for v in VALUES:
            self.assertNotIn(v.value, str(ctx.exception))

    def test_cleared_registry_detects_nothing(self) -> None:
        r = registry()
        r.clear()
        self.assertEqual(r.find(VALUES[0].value), [])
        self.assertEqual(list(r.values()), [])

    def test_hostile_input_does_not_hang_or_crash(self) -> None:
        r = registry()
        for text in ("\x00" * 100_000, "[REDACTED:" * 10_000, "\ud800" * 1000, " " * 200_000):
            r.redact(text)
            r.find(text)
        text = "[REDACTED:sv_00000000]" + VALUES[0].value
        self.assertNotIn(VALUES[0].value, r.redact(text))
