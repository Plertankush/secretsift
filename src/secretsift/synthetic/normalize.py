"""Pure variant-building functions: every encoding a value may take inside a payload."""

from __future__ import annotations

import base64
import json
import re
from urllib.parse import quote, quote_plus

from secretsift.models import Variant

MIN_ENCODED_LEN = 6  # shorter encoded needles would be too ambiguous to report
MAX_WS_PATTERN_VALUE = 1024  # cap for the whitespace-tolerant regex
_URLSAFE = str.maketrans("+/", "-_")
_B64_SKIP = (0, 2, 3)  # leading chars that depend on unknown preceding bytes (per alignment)
_B64_TAIL = (0, 1, 2)  # trailing chars that are fixed when 0/1/2 bytes remain in a group
_PCT_HEX = re.compile(r"%[0-9A-F]{2}")


def strip_whitespace(value: str) -> str:
    """Remove every whitespace character."""
    return "".join(value.split())


def url_forms(value: str) -> list[str]:
    """``quote`` and ``quote_plus`` encodings, upper- and lowercase percent escapes."""
    forms = [quote(value, safe=""), quote(value), quote_plus(value)]
    forms += [_PCT_HEX.sub(lambda m: m.group().lower(), f) for f in forms]
    return forms


def base64_forms(value: str) -> list[str]:
    """Padding-free base64 (standard and urlsafe) for each of the 3 byte alignments."""
    data = value.encode("utf-8")
    forms: list[str] = []
    for shift in range(3):
        encoded = base64.b64encode(b"\0" * shift + data).decode("ascii").rstrip("=")
        total = shift + len(data)
        needle = encoded[_B64_SKIP[shift] : 4 * (total // 3) + _B64_TAIL[total % 3]]
        forms += [needle, needle.translate(_URLSAFE)]
    return forms


def hex_forms(value: str) -> list[str]:
    """Lowercase and uppercase hex of the UTF-8 bytes."""
    digits = value.encode("utf-8").hex()
    return [digits, digits.upper()]


def json_forms(value: str) -> list[str]:
    """Contents of a JSON string literal: ASCII-escaped, unicode-preserving, slash-escaped."""
    ascii_form = json.dumps(value, ensure_ascii=True)[1:-1]
    utf_form = json.dumps(value, ensure_ascii=False)[1:-1]
    return [ascii_form, utf_form, ascii_form.replace("/", "\\/"), utf_form.replace("/", "\\/")]


def encoded_needles(value: str) -> list[tuple[Variant, str]]:
    """All exact-substring variants (excluding raw, casefold and whitespace)."""
    groups = (
        (Variant.URL_ENCODED, url_forms(value)),
        (Variant.BASE64, base64_forms(value)),
        (Variant.HEX, hex_forms(value)),
        (Variant.JSON_ESCAPED, json_forms(value)),
    )
    needles: list[tuple[Variant, str]] = []
    seen = {value}
    for variant, forms in groups:
        for form in forms:
            if form not in seen and len(form) >= MIN_ENCODED_LEN:
                seen.add(form)
                needles.append((variant, form))
    return needles


def casefold_pattern(value: str) -> re.Pattern[str]:
    """Case-insensitive literal pattern (offsets stay valid on the original text)."""
    return re.compile(re.escape(value), re.IGNORECASE)


def whitespace_pattern(value: str) -> re.Pattern[str] | None:
    """Pattern matching the value with arbitrary whitespace between any two characters."""
    stripped = strip_whitespace(value)
    if not stripped or len(stripped) > MAX_WS_PATTERN_VALUE:
        return None
    return re.compile(r"\s*".join(re.escape(ch) for ch in stripped))
