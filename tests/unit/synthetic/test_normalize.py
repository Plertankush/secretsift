"""Pure variant builders."""

from __future__ import annotations

import base64
import unittest

from secretsift.models import Variant
from secretsift.synthetic import normalize as n


class NormalizeTests(unittest.TestCase):
    def test_base64_alignments_appear_in_real_encodings(self) -> None:
        value = "sk-test-abcdef123456"
        forms = n.base64_forms(value)
        for prefix_len in range(3):
            for suffix in (b"", b"x", b"xy", b"xyz"):
                blob = base64.b64encode(b"Q" * prefix_len + value.encode() + suffix).decode()
                self.assertTrue(any(f in blob for f in forms), (prefix_len, suffix))

    def test_base64_urlsafe_alphabet(self) -> None:
        value = "???>>>~~~???>>>"  # produces + and / in standard base64
        std = base64.b64encode(value.encode()).decode().rstrip("=")
        self.assertIn("+", std + "/")
        urlsafe = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        forms = n.base64_forms(value)
        self.assertTrue(any(f in std for f in forms))
        self.assertTrue(any(f in urlsafe for f in forms))

    def test_url_forms(self) -> None:
        forms = n.url_forms("a b/c#d")
        self.assertIn("a%20b%2Fc%23d", forms)
        self.assertIn("a+b%2Fc%23d", forms)
        self.assertIn("a%20b/c%23d", forms)
        self.assertIn("a%20b%2fc%23d", forms)

    def test_hex_and_json(self) -> None:
        self.assertEqual(n.hex_forms("Az"), ["417a", "417A"])
        forms = n.json_forms('a"b\\c\n/é')
        self.assertIn('a\\"b\\\\c\\n/\\u00e9', forms)
        self.assertIn('a\\"b\\\\c\\n\\/é', forms)

    def test_encoded_needles_filters_short_and_identical(self) -> None:
        self.assertEqual([v for v, _ in n.encoded_needles("ab")], [])
        needles = n.encoded_needles("plain-value-xyz")
        self.assertNotIn("plain-value-xyz", [t for _, t in needles])
        self.assertEqual(len({t for _, t in needles}), len(needles))
        self.assertTrue({Variant.BASE64, Variant.HEX} <= {v for v, _ in needles})

    def test_whitespace_pattern(self) -> None:
        pat = n.whitespace_pattern("ab cd")
        assert pat is not None
        self.assertIsNotNone(pat.fullmatch("a \n b\tc  d"))
        self.assertIsNotNone(pat.fullmatch("abcd"))
        self.assertIsNone(n.whitespace_pattern("   "))
        self.assertIsNone(n.whitespace_pattern("x" * 2000))

    def test_casefold_pattern_escapes(self) -> None:
        pat = n.casefold_pattern("a.b+c")
        self.assertIsNotNone(pat.fullmatch("A.B+C"))
        self.assertIsNone(pat.fullmatch("axb+c"))

    def test_strip_whitespace(self) -> None:
        self.assertEqual(n.strip_whitespace(" a\tb\nc d "), "abcd")
