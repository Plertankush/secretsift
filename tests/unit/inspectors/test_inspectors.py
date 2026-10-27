"""Inspector tests using the real SecretRegistry and generator."""

from __future__ import annotations

import base64
import datetime as dt
import unittest
import urllib.parse

from secretsift.contracts import Inspector
from secretsift.inspectors import (
    AIOutputInspector,
    AIRequestInspector,
    ErrorInspector,
    HttpInspector,
    LogInspector,
    PayloadInspector,
    StorageInspector,
    default_inspectors,
)
from secretsift.models import DataType, Destination, Event, SyntheticValue, Variant
from secretsift.synthetic.generator import generate_value
from secretsift.synthetic.registry import SecretRegistry

EXPECTED = {
    "logs": Destination.APPLICATION_LOGS,
    "errors": Destination.ERROR_REPORT,
    "http": Destination.HTTP_REQUEST,
    "ai_requests": Destination.AI_REQUEST,
    "ai_outputs": Destination.AI_OUTPUT,
    "storage": Destination.STORAGE,
}


def make_event(destination: Destination, payload: str, **kwargs: object) -> Event:
    return Event(
        id="ev_1",
        destination=destination,
        component="app",
        timestamp=dt.datetime.now(dt.UTC),
        payload=payload,
        **kwargs,  # type: ignore[arg-type]
    )


class InspectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = SecretRegistry()
        self.sv: SyntheticValue = generate_value(
            "customer_api_key", DataType.API_KEY, run_id="run1", seed=7
        )
        self.registry.register(self.sv)
        self.inspectors = {i.name: i for i in default_inspectors()}

    def test_default_inspectors_names_and_destinations(self) -> None:
        inspectors = default_inspectors()
        self.assertEqual([i.name for i in inspectors], list(EXPECTED))
        for insp in inspectors:
            self.assertIsInstance(insp, Inspector)
            self.assertIsInstance(insp, PayloadInspector)
            self.assertEqual(insp.destinations, frozenset({EXPECTED[insp.name]}))

    def test_each_inspector_finds_raw_with_offsets(self) -> None:
        for name, dest in EXPECTED.items():
            payload = f"prefix {self.sv.value} suffix"
            matches = self.inspectors[name].inspect(make_event(dest, payload), self.registry)
            self.assertEqual(len(matches), 1, name)
            m = matches[0]
            self.assertEqual(m.value_id, self.sv.id)
            self.assertEqual(m.variant, Variant.RAW)
            self.assertEqual(payload[m.start : m.end], self.sv.value)

    def test_each_inspector_ignores_other_destinations(self) -> None:
        for name, insp in self.inspectors.items():
            for dest in Destination:
                if dest == EXPECTED[name]:
                    continue
                event = make_event(dest, f"leak {self.sv.value}")
                self.assertEqual(insp.inspect(event, self.registry), [], (name, dest))

    def test_encoded_variants(self) -> None:
        forms = {
            Variant.URL_ENCODED: urllib.parse.quote(self.sv.value, safe=""),
            Variant.BASE64: base64.b64encode(self.sv.value.encode()).decode(),
            Variant.HEX: self.sv.value.encode().hex(),
        }
        for name, dest in EXPECTED.items():
            for variant, text in forms.items():
                if text == self.sv.value:
                    continue
                payload = f"x={text}&y=1"
                matches = self.inspectors[name].inspect(make_event(dest, payload), self.registry)
                self.assertTrue(matches, (name, variant))
                self.assertEqual(matches[0].variant, variant)
                self.assertEqual(payload[matches[0].start : matches[0].end], text)

    def test_clean_text_has_no_findings(self) -> None:
        clean = "GET /health 200 user=alice request completed in 12ms [REDACTED:sv_deadbeef]"
        for name, dest in EXPECTED.items():
            self.assertEqual(
                self.inspectors[name].inspect(make_event(dest, clean), self.registry), []
            )
            self.assertEqual(self.inspectors[name].inspect(make_event(dest, ""), self.registry), [])

    def test_multiple_values_and_occurrences(self) -> None:
        other = generate_value("pw", DataType.PASSWORD, run_id="run1", seed=7)
        self.registry.register(other)
        payload = f"{self.sv.value} and {other.value} and {self.sv.value}"
        matches = LogInspector().inspect(
            make_event(Destination.APPLICATION_LOGS, payload), self.registry
        )
        ids = sorted(m.value_id for m in matches)
        self.assertEqual(ids, sorted([self.sv.id, other.id, self.sv.id]))
        for m in matches:
            self.assertIn(payload[m.start : m.end], (self.sv.value, other.value))

    def test_http_all_parts_and_approved_flag(self) -> None:
        insp = HttpInspector()
        for part in ("url", "headers", "body"):
            event = make_event(
                Destination.HTTP_REQUEST,
                f"http://x/?k={self.sv.value}",
                metadata={"part": part},
                approved=part == "body",
            )
            self.assertEqual(len(insp.inspect(event, self.registry)), 1, part)

    def test_ai_output_chunks_and_aggregated_stream(self) -> None:
        insp = AIOutputInspector()
        half = len(self.sv.value) // 2
        chunks = [self.sv.value[:half], self.sv.value[half:]]
        for i, chunk in enumerate(chunks):
            event = make_event(Destination.AI_OUTPUT, chunk, metadata={"chunk_index": i})
            self.assertEqual(insp.inspect(event, self.registry), [])
        agg = make_event(Destination.AI_OUTPUT, "".join(chunks), metadata={"aggregated": True})
        matches = insp.inspect(agg, self.registry)
        self.assertEqual(len(matches), 1)
        self.assertEqual((matches[0].start, matches[0].end), (0, len(self.sv.value)))

    def test_repr_has_no_payload(self) -> None:
        event = make_event(Destination.APPLICATION_LOGS, self.sv.value)
        self.assertNotIn(self.sv.value, repr(event))
        self.assertNotIn(self.sv.value, repr(self.inspectors["logs"]))

    def test_individual_classes(self) -> None:
        pairs = [
            (LogInspector, Destination.APPLICATION_LOGS),
            (ErrorInspector, Destination.ERROR_REPORT),
            (AIRequestInspector, Destination.AI_REQUEST),
            (StorageInspector, Destination.STORAGE),
        ]
        for cls, dest in pairs:
            self.assertEqual(cls().destinations, frozenset({dest}))


if __name__ == "__main__":
    unittest.main()
