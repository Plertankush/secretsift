"""build_evidence, redact_text and redact_credentials."""

from __future__ import annotations

import datetime as dt
import unittest

from secretsift.evidence import build_evidence, redact_credentials, redact_text
from secretsift.models import DataType, Destination, Event
from secretsift.synthetic import SecretRegistry, generate_value

KEY = generate_value("key", DataType.API_KEY, run_id="r", seed=1)
PW = generate_value("pw", DataType.PASSWORD, run_id="r", seed=1)


def event(payload: str) -> Event:
    return Event(
        id="ev_1",
        destination=Destination.APPLICATION_LOGS,
        component="app",
        timestamp=dt.datetime.now(dt.UTC),
        payload=payload,
    )


def registry() -> SecretRegistry:
    r = SecretRegistry()
    r.register(KEY)
    r.register(PW)
    return r


class BuildEvidenceTests(unittest.TestCase):
    def evidence(self, payload: str, window: int = 40) -> str:
        r = registry()
        return build_evidence(event(payload), r.find(payload), r, window)

    def test_basic_snippet(self) -> None:
        out = self.evidence(f"login ok key={KEY.value} done")
        self.assertEqual(out, f"login ok key=[REDACTED:{KEY.id}] done")

    def test_ellipsis_when_cut(self) -> None:
        pad = "x" * 100
        out = self.evidence(f"{pad}{KEY.value}{pad}")
        self.assertTrue(out.startswith("..."))
        self.assertTrue(out.endswith("..."))
        self.assertIn(f"[REDACTED:{KEY.id}]", out)
        self.assertNotIn("...", self.evidence(f"a {KEY.value} b"))

    def test_no_leak_when_window_edge_cuts_value(self) -> None:
        for window in range(0, 60):
            for text in (
                f"{'p' * 70}{KEY.value}{'q' * 70}",
                f"{KEY.value}{'z' * 3}{KEY.value}",
                f"{'z' * 10}{KEY.value}{'z' * 3}{PW.value}{'z' * 3}{KEY.value}",
            ):
                out = self.evidence(text, window)
                for v in (KEY, PW):
                    self.assertNotIn(v.value, out)
                    for k in range(6, len(v.value)):
                        self.assertNotIn(v.value[:k], out, (window, k))
                        self.assertNotIn(v.value[-k:], out, (window, k))

    def test_stale_or_partial_matches_still_safe(self) -> None:
        text = f"{KEY.value} and {PW.value}"
        r = registry()
        only_first = [m for m in r.find(text) if m.value_id == KEY.id]
        out = build_evidence(event(text), only_first, r, 100)
        self.assertNotIn(PW.value, out)
        out = build_evidence(event(text), [], r, 100)
        self.assertNotIn(KEY.value, out)

    def test_variant_not_leaked_at_edge(self) -> None:
        import base64

        blob = base64.b64encode(b"z" + KEY.value.encode()).decode()
        text = "j" * 50 + blob + "k" * 50
        out = self.evidence(text, 10)
        self.assertNotIn(blob[8:], out)
        self.assertIn("[REDACTED:", out)

    def test_control_chars_made_printable(self) -> None:
        out = self.evidence(f"a\nb\r\tc\x00\x1b[31m {KEY.value}")
        self.assertNotRegex(out, r"[\x00-\x1f\x7f]")
        self.assertIn("\\n", out)
        self.assertIn("\\x00", out)
        self.assertIn("\\x1b", out)

    def test_max_length(self) -> None:
        out = self.evidence("A" * 1000 + KEY.value + "B" * 1000, window=500)
        self.assertLessEqual(len(out), 240)
        self.assertTrue(out.endswith("..."))
        self.assertLessEqual(len(self.evidence("A" * 5000, window=5000)), 240)

    def test_no_matches_gives_head_of_payload(self) -> None:
        out = self.evidence("hello " * 100, window=10)
        self.assertTrue(out.startswith("hello"))
        self.assertTrue(out.endswith("..."))
        self.assertEqual(self.evidence(""), "")

    def test_first_match_anchors(self) -> None:
        out = self.evidence("start " + KEY.value + " " * 300 + PW.value, window=10)
        self.assertIn(KEY.id, out)
        self.assertNotIn(PW.id, out)

    def test_adjacent_and_overlapping_spans(self) -> None:
        out = self.evidence(KEY.value + PW.value)
        self.assertEqual(out, f"[REDACTED:{KEY.id}][REDACTED:{PW.id}]")

    def test_credentials_in_snippet_masked(self) -> None:
        out = self.evidence(f"Authorization: Bearer abc123def456ghi {KEY.value}")
        self.assertNotIn("abc123def456ghi", out)
        self.assertIn(f"[REDACTED:{KEY.id}]", out)

    def test_negative_window_is_clamped(self) -> None:
        self.assertNotIn(KEY.value, self.evidence(f"a{KEY.value}b", window=-5))


class RedactTextTests(unittest.TestCase):
    def test_delegates_to_registry(self) -> None:
        r = registry()
        self.assertEqual(redact_text(f"x {KEY.value}", r), f"x [REDACTED:{KEY.id}]")


class RedactCredentialsTests(unittest.TestCase):
    def test_masks_known_forms(self) -> None:
        cases = {
            "key sk-abc123def456ghi789jkl0 end": "sk-abc123def456ghi789jkl0",
            "key sk-proj-AbCdEfGhIjKlMnOpQrStUv end": "sk-proj-AbCdEfGhIjKlMnOpQrStUv",
            "Authorization: Bearer eyJhbGciOi.eyJzdWIi.sig123": "eyJhbGciOi",
            "Authorization: Basic dXNlcjpwYXNz": "dXNlcjpwYXNz",
            '"Authorization": "Token abcdef123456"': "abcdef123456",
            "authorization=rawsecretvalue99": "rawsecretvalue99",
            "GET /x?api_key=abcd1234efgh&q=1": "abcd1234efgh",
            "api-key: Zm9vYmFyYmF6cXV4cXV1eA==": "Zm9vYmFyYmF6cXV4cXV1eA",
            "X-Api-Key: 0123456789abcdef": "0123456789abcdef",
            "x-goog-api-key=AIzaSyA1234567890abcdefghij": "AIzaSyA1234567890abcdefghij",
            'password="hunter2hunter2"': "hunter2hunter2",
            "access_token=ghp_abcdefghijklmnopqrstuv": "ghp_abcdefghijklmnopqrstuv",
            "use Bearer abc.def-123_456 now": "abc.def-123_456",
            "sk_live_abcdefgh12345678": "sk_live_abcdefgh12345678",
            "AKIAABCDEFGHIJKLMNOP": "AKIAABCDEFGHIJKLMNOP",
        }
        for text, secret in cases.items():
            out = redact_credentials(text)
            self.assertNotIn(secret, out, text)
            self.assertIn("[REDACTED:credential]", out, text)

    def test_keeps_context_and_key_names(self) -> None:
        self.assertEqual(
            redact_credentials("Authorization: Bearer abc.def-123_456"),
            "Authorization: Bearer [REDACTED:credential]",
        )
        self.assertEqual(
            redact_credentials("GET /x?api_key=abcd1234efgh&q=1"),
            "GET /x?api_key=[REDACTED:credential]&q=1",
        )

    def test_unrelated_text_untouched(self) -> None:
        for text in (
            "The bearer authentication scheme is described in RFC 6750.",
            "This task-based risk-assessment is ask-me-anything friendly.",
            "Use scikit-learn; sk-learn is not a key.",
            "Please set a strong password and rotate the token regularly.",
            "token: no, key is fine; secret ingredient",
            "Bearer of bad news",
            "price=100&currency=USD",
            "def f(api_key): return api_key",
            "",
        ):
            self.assertEqual(redact_credentials(text), text, text)

    def test_idempotent(self) -> None:
        text = (
            "Authorization: Bearer abc.def-123_456\napi_key=abcd1234efgh sk-abc123def456ghi789jkl0"
        )
        once = redact_credentials(text)
        self.assertEqual(redact_credentials(once), once)

    def test_does_not_touch_registry_tokens(self) -> None:
        text = f"api_key=[REDACTED:{KEY.id}] token: [REDACTED:{PW.id}]"
        self.assertEqual(redact_credentials(text), text)

    def test_large_input_is_fast(self) -> None:
        import time

        text = ("word " * 10 + "sk-notakey ") * 20000
        start = time.perf_counter()
        redact_credentials(text)
        self.assertLess(time.perf_counter() - start, 1.5)
        start = time.perf_counter()
        redact_credentials("Bearer " + "a" * 500_000)
        redact_credentials("sk-" + "a" * 500_000 + "!")
        self.assertLess(time.perf_counter() - start, 1.5)
