"""SecretRegistry: variants, offsets, redaction, performance, threads."""

from __future__ import annotations

import base64
import json
import re
import threading
import time
import unittest
from urllib.parse import quote, quote_plus

from secretsift.contracts import SecretRegistryProtocol
from secretsift.exceptions import ConfigError
from secretsift.models import DataType, Match, SyntheticValue, Variant
from secretsift.synthetic import SecretRegistry, generate_value

KEY = generate_value("key", DataType.API_KEY, run_id="r", seed=1)
PW = generate_value("pw", DataType.PASSWORD, run_id="r", seed=1)
NAME = generate_value("name", DataType.NAME, run_id="r", seed=1)


def make(value: str, vid: str = "sv_00000001") -> SyntheticValue:
    return SyntheticValue(
        id=vid, data_type=DataType.CUSTOM, label="c", value=value, marker="m" * 8, run_id="r"
    )


def reg(*values: SyntheticValue) -> SecretRegistry:
    r = SecretRegistry()
    for v in values:
        r.register(v)
    return r


class FindTests(unittest.TestCase):
    def check(self, v: SyntheticValue, encoded: str, variant: Variant, pre: str = "pre ") -> None:
        text = f"{pre}{encoded} post"
        ms = reg(v).find(text)
        self.assertEqual(len(ms), 1, (variant, ms))
        m = ms[0]
        self.assertEqual((m.value_id, m.variant), (v.id, variant))
        self.assertEqual(text[m.start : m.end], encoded)

    def test_protocol(self) -> None:
        self.assertIsInstance(SecretRegistry(), SecretRegistryProtocol)

    def test_raw_with_offsets(self) -> None:
        self.check(KEY, KEY.value, Variant.RAW)
        ms = reg(KEY).find(f"{KEY.value}|{KEY.value}")
        self.assertEqual([m.start for m in ms], [0, len(KEY.value) + 1])

    def test_casefold(self) -> None:
        self.check(KEY, KEY.value.upper(), Variant.CASEFOLD)
        self.check(NAME, NAME.value.lower(), Variant.CASEFOLD)

    def test_casefold_with_length_changing_text(self) -> None:
        text = "STRASSE İ " + KEY.value.upper()  # 'İ'.lower() changes the length
        ms = reg(KEY).find(text)
        self.assertEqual(len(ms), 1)
        self.assertEqual(text[ms[0].start : ms[0].end], KEY.value.upper())

    def test_url_encoded(self) -> None:
        self.check(PW, quote(PW.value, safe=""), Variant.URL_ENCODED)
        self.check(PW, quote_plus(PW.value), Variant.URL_ENCODED)
        lower_pct = re.sub(r"%[0-9A-F]{2}", lambda m: m.group().lower(), quote(PW.value, safe=""))
        self.check(PW, lower_pct, Variant.URL_ENCODED)
        spaced = make("hello world&x=1")
        self.check(spaced, quote_plus(spaced.value), Variant.URL_ENCODED)
        self.check(spaced, quote(spaced.value), Variant.URL_ENCODED)

    def test_base64_all_alignments_std_and_urlsafe(self) -> None:
        value = make("tok/en>>>??+secret-123")
        r = reg(value)
        for pad in range(3):
            for suffix in (b"", b"!", b"!!", b"!!!"):
                raw = b"\xfe" * pad + value.value.encode() + suffix
                for enc in (base64.b64encode, base64.urlsafe_b64encode):
                    for strip in (False, True):
                        blob = enc(raw).decode()
                        blob = blob.rstrip("=") if strip else blob
                        text = f"data={blob};"
                        ms = r.find(text)
                        self.assertEqual(len(ms), 1, (pad, suffix, enc.__name__, strip))
                        self.assertEqual(ms[0].variant, Variant.BASE64)
                        self.assertGreater(ms[0].end, ms[0].start)

    def test_base64_whole_exact_offsets(self) -> None:
        enc = base64.b64encode(KEY.value.encode()).decode()
        ms = reg(KEY).find("x" + enc)
        self.assertEqual(ms[0].variant, Variant.BASE64)
        self.assertGreaterEqual(ms[0].start, 1)
        self.assertLessEqual(ms[0].end, 1 + len(enc))

    def test_hex(self) -> None:
        hx = KEY.value.encode().hex()
        self.check(KEY, hx, Variant.HEX)
        self.check(KEY, hx.upper(), Variant.HEX)

    def test_json_escaped(self) -> None:
        v = make('pa"ss\\w/ord\né-12345')
        self.check(v, json.dumps(v.value)[1:-1], Variant.JSON_ESCAPED)
        self.check(v, json.dumps(v.value, ensure_ascii=False)[1:-1], Variant.JSON_ESCAPED)
        self.check(v, json.dumps(v.value)[1:-1].replace("/", "\\/"), Variant.JSON_ESCAPED)

    def test_whitespace_stripped(self) -> None:
        for sep in (" ", "\n", "\t ", "\r\n  "):
            half = len(KEY.value) // 2
            spaced = KEY.value[:half] + sep + KEY.value[half:]
            self.check(KEY, spaced, Variant.WHITESPACE_STRIPPED)
        many = " ".join(KEY.value)
        self.check(KEY, many, Variant.WHITESPACE_STRIPPED)

    def test_value_containing_spaces_and_stripped_form(self) -> None:
        v = make("Alice Q Smith 42")
        self.check(v, "Alice Q Smith 42", Variant.RAW)
        self.check(v, "AliceQSmith42", Variant.WHITESPACE_STRIPPED)
        self.check(v, "Alice  Q\nSmith 42", Variant.WHITESPACE_STRIPPED)

    def test_offsets_refer_to_original_text(self) -> None:
        text = "éé " + KEY.value.upper() + " ☃ " + quote(PW.value, safe="")
        ms = reg(KEY, PW).find(text)
        self.assertEqual([m.value_id for m in ms], [KEY.id, PW.id])
        self.assertEqual(text[ms[0].start : ms[0].end], KEY.value.upper())
        self.assertEqual(text[ms[1].start : ms[1].end], quote(PW.value, safe=""))

    def test_sorted_and_multi_value(self) -> None:
        text = f"{PW.value} {KEY.value} {NAME.value}"
        ms = reg(KEY, PW, NAME).find(text)
        self.assertEqual([m.value_id for m in ms], [PW.id, KEY.id, NAME.id])
        self.assertEqual(ms, sorted(ms, key=lambda m: m.start))

    def test_overlaps_merged_per_value(self) -> None:
        v = make("abcdefghij")
        ms = reg(v).find("xx abcdefghij yy a b c d e f g h i j")
        self.assertEqual(len(ms), 2)
        self.assertEqual(ms[0].variant, Variant.RAW)
        self.assertEqual(ms[1].variant, Variant.WHITESPACE_STRIPPED)

    def test_overlapping_different_values_both_reported(self) -> None:
        a, b = make("abcdefgh", "sv_aaaaaaaa"), make("efghijkl", "sv_bbbbbbbb")
        ms = reg(a, b).find("abcdefghijkl")
        self.assertEqual({m.value_id for m in ms}, {"sv_aaaaaaaa", "sv_bbbbbbbb"})

    def test_no_false_positives(self) -> None:
        r = reg(KEY, PW, NAME)
        for text in (
            "",
            "hello world, nothing to see",
            "sk-test-other-value 1234567890 abcdef",
            "Tp!&# password",
            base64.b64encode(b"completely unrelated payload bytes here").decode(),
            "deadbeef " * 50,
            KEY.value[:-3],
            KEY.value[3:],
        ):
            self.assertEqual(r.find(text), [], text)

    def test_empty_registry_and_text(self) -> None:
        self.assertEqual(SecretRegistry().find("anything"), [])
        self.assertEqual(reg(KEY).find(""), [])

    def test_regex_metacharacters_in_values(self) -> None:
        v = make("a.b*c+d?(e)[f]{g}|h^$\\i")
        r = reg(v)
        self.assertEqual(len(r.find(f"[{v.value}]")), 1)
        self.assertEqual(r.find("axb"), [])
        self.assertEqual(r.redact("<" + v.value + ">"), f"<[REDACTED:{v.id}]>")


class RedactTests(unittest.TestCase):
    ALL = [KEY, PW, NAME]

    def texts(self) -> list[str]:
        k = KEY.value
        return [
            f"plain {k} tail",
            f"UP {k.upper()} tail",
            f"url {quote_plus(PW.value)} and {quote(PW.value, safe='')}",
            f"b64 {base64.b64encode(b'x' + k.encode()).decode()}",
            f"hex {k.encode().hex()} {k.encode().hex().upper()}",
            f"json {json.dumps({'k': PW.value})}",
            f"split {k[:10]}\n  {k[10:]}",
            f"{k}{k}{PW.value}",
            f"{NAME.value} / {NAME.value.replace(' ', '')}",
        ]

    def test_redact_removes_all_and_is_idempotent(self) -> None:
        r = reg(*self.ALL)
        for text in self.texts():
            self.assertTrue(r.find(text), text)
            out = r.redact(text)
            self.assertEqual(r.find(out), [], out)
            self.assertEqual(r.redact(out), out)
            for v in self.ALL:
                self.assertNotIn(v.value, out)

    def test_token_format(self) -> None:
        self.assertEqual(reg(KEY).redact(f"a {KEY.value} b"), f"a [REDACTED:{KEY.id}] b")

    def test_unrelated_text_unchanged(self) -> None:
        text = "nothing secret here, just words"
        self.assertEqual(reg(KEY).redact(text), text)

    def test_redaction_token_is_not_rematched(self) -> None:
        v = make("REDACTED")
        r = reg(v)
        out = r.redact("a REDACTED b")
        self.assertEqual(r.find(out), [])
        self.assertEqual(r.redact(out), out)

    def test_overlapping_values_both_tokens(self) -> None:
        a, b = make("abcdefgh", "sv_aaaaaaaa"), make("efghijkl", "sv_bbbbbbbb")
        r = reg(a, b)
        out = r.redact("x abcdefghijkl y")
        self.assertEqual(out, "x [REDACTED:sv_aaaaaaaa][REDACTED:sv_bbbbbbbb] y")
        self.assertEqual(r.find(out), [])


class LifecycleTests(unittest.TestCase):
    def test_register_get_values_clear(self) -> None:
        r = reg(KEY)
        self.assertEqual(r.get(KEY.id), KEY)
        self.assertEqual(list(r.values()), [KEY])
        with self.assertRaises(KeyError):
            r.get("sv_missing0")
        r.clear()
        self.assertEqual(list(r.values()), [])
        self.assertEqual(r.find(KEY.value), [])

    def test_reregister_replaces(self) -> None:
        r = reg(make("first-value-123", "sv_dup00000"))
        r.register(make("second-value-456", "sv_dup00000"))
        self.assertEqual(r.find("first-value-123"), [])
        self.assertEqual(len(r.find("second-value-456")), 1)
        self.assertEqual(len(r.values()), 1)

    def test_empty_value_rejected(self) -> None:
        with self.assertRaises(ConfigError):
            SecretRegistry().register(make(""))

    def test_repr_hides_values(self) -> None:
        self.assertNotIn(KEY.value, repr(reg(KEY)))

    def test_match_type(self) -> None:
        self.assertIsInstance(reg(KEY).find(KEY.value)[0], Match)


class ConcurrencyAndPerfTests(unittest.TestCase):
    def test_thread_safety(self) -> None:
        r = SecretRegistry()
        errors: list[BaseException] = []
        vals = [generate_value(f"l{i}", DataType.API_KEY, run_id="r", seed=2) for i in range(40)]

        def writer(chunk: list[SyntheticValue]) -> None:
            try:
                for v in chunk:
                    r.register(v)
            except BaseException as exc:  # pragma: no cover
                errors.append(exc)

        def reader() -> None:
            try:
                for _ in range(50):
                    for m in r.find(" ".join(v.value for v in vals)):
                        self.assertIn(m.value_id, {v.id for v in vals})
                    r.redact(vals[0].value)
            except BaseException as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(vals[i::4],)) for i in range(4)]
        threads += [threading.Thread(target=reader) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(r.values()), 40)
        self.assertEqual(len(r.find(" ".join(v.value for v in vals))), 40)

    def test_one_megabyte_scan_is_fast(self) -> None:
        values = [
            generate_value(f"v{i}", dt, run_id="r", seed=3)
            for i, dt in enumerate(
                [
                    DataType.API_KEY,
                    DataType.PASSWORD,
                    DataType.EMAIL,
                    DataType.NAME,
                    DataType.SESSION_ID,
                    DataType.CUSTOMER_ID,
                ]
            )
        ]
        r = reg(*values)
        filler = "The quick brown fox jumps over the lazy dog. user=alice id=42\n" * 17000
        text = filler[:500_000] + values[0].value + filler[500_000:]
        self.assertGreater(len(text), 1_000_000)
        start = time.perf_counter()
        ms = r.find(text)
        elapsed = time.perf_counter() - start
        self.assertEqual(len(ms), 1)
        self.assertEqual(text[ms[0].start : ms[0].end], values[0].value)
        self.assertLess(elapsed, 1.0)
        start = time.perf_counter()
        out = r.redact(text)
        self.assertLess(time.perf_counter() - start, 1.5)
        self.assertNotIn(values[0].value, out)

    def test_pathological_repetition_is_linear(self) -> None:
        r = reg(make("aaaaaaaaaaaa"))
        text = "a" * 1_000_000
        start = time.perf_counter()
        r.find(text)
        self.assertLess(time.perf_counter() - start, 2.0)
        text = " " * 1_000_000
        start = time.perf_counter()
        r.find(text)
        self.assertLess(time.perf_counter() - start, 1.0)
