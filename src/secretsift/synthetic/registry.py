"""Thread-safe registry of active synthetic values with variant-aware search."""

from __future__ import annotations

import re
import threading
from collections.abc import Sequence
from dataclasses import dataclass

from secretsift.exceptions import ConfigError
from secretsift.models import Match, SyntheticValue, Variant
from secretsift.synthetic import normalize

_RANK = {variant: rank for rank, variant in enumerate(Variant)}
_TOKEN_RE = re.compile(r"\[REDACTED:[A-Za-z0-9_.-]+\]")
_MAX_PASSES = 4


@dataclass(frozen=True)
class _Compiled:
    """Search material for one value, built once at registration."""

    value_id: str
    value: str
    lowered: str
    exact: tuple[tuple[Variant, str], ...]
    ws: re.Pattern[str] | None


def _compile(sv: SyntheticValue) -> _Compiled:
    return _Compiled(
        value_id=sv.id,
        value=sv.value,
        lowered=sv.value.lower(),
        exact=tuple(normalize.encoded_needles(sv.value)),
        ws=normalize.whitespace_pattern(sv.value),
    )


_Hit = tuple[int, int, Variant]


def _scan_exact(text: str, needle: str, variant: Variant, out: list[_Hit]) -> None:
    pos = text.find(needle)
    while pos != -1:
        end = pos + len(needle)
        out.append((pos, end, variant))
        pos = text.find(needle, end)


def _scan(c: _Compiled, text: str, lowered: str | None) -> list[tuple[int, int, Variant]]:
    hits: list[tuple[int, int, Variant]] = []
    _scan_exact(text, c.value, Variant.RAW, hits)
    if lowered is not None and len(c.lowered) == len(c.value):
        pos = lowered.find(c.lowered)
        while pos != -1:
            end = pos + len(c.lowered)
            if text[pos:end] != c.value:
                hits.append((pos, end, Variant.CASEFOLD))
            pos = lowered.find(c.lowered, end)
    else:
        for m in normalize.casefold_pattern(c.value).finditer(text):
            if m.group() != c.value:
                hits.append((m.start(), m.end(), Variant.CASEFOLD))
    for variant, needle in c.exact:
        _scan_exact(text, needle, variant, hits)
    if c.ws is not None:
        hits.extend((m.start(), m.end(), Variant.WHITESPACE_STRIPPED) for m in c.ws.finditer(text))
    return hits


def _merge(hits: list[tuple[int, int, Variant]]) -> list[tuple[int, int, Variant]]:
    """Union overlapping spans; the strongest (lowest-rank) variant labels the result."""
    merged: list[tuple[int, int, Variant]] = []
    for start, end, variant in sorted(hits, key=lambda h: (h[0], h[1])):
        if merged and start < merged[-1][1]:
            p_start, p_end, p_variant = merged[-1]
            best = variant if _RANK[variant] < _RANK[p_variant] else p_variant
            merged[-1] = (p_start, max(p_end, end), best)
        else:
            merged.append((start, end, variant))
    return merged


class SecretRegistry:
    """Tracks active synthetic values; implements ``SecretRegistryProtocol``."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._values: dict[str, SyntheticValue] = {}
        self._compiled: tuple[_Compiled, ...] = ()

    def __repr__(self) -> str:
        return f"SecretRegistry(values={len(self._values)})"

    def register(self, value: SyntheticValue) -> None:
        """Add (or replace, by id) a value. Empty values are rejected."""
        if not value.value:
            raise ConfigError("cannot register an empty synthetic value")
        compiled = _compile(value)
        with self._lock:
            self._values[value.id] = value
            kept = tuple(c for c in self._compiled if c.value_id != value.id)
            self._compiled = (*kept, compiled)

    def get(self, value_id: str) -> SyntheticValue:
        with self._lock:
            try:
                return self._values[value_id]
            except KeyError:
                raise KeyError(f"unknown synthetic value id: {value_id}") from None

    def values(self) -> Sequence[SyntheticValue]:
        with self._lock:
            return list(self._values.values())

    def clear(self) -> None:
        with self._lock:
            self._values.clear()
            self._compiled = ()

    def find(self, text: str) -> list[Match]:
        """All matches (raw and variants) with offsets into ``text``, sorted by start."""
        with self._lock:
            compiled = self._compiled
        if not text or not compiled:
            return []
        lowered_text = text.lower()
        lowered: str | None = lowered_text if len(lowered_text) == len(text) else None
        tokens = [m.span() for m in _TOKEN_RE.finditer(text)] if "[REDACTED:" in text else []
        matches: list[Match] = []
        for c in compiled:
            for start, end, variant in _merge(_scan(c, text, lowered)):
                if any(ts <= start and end <= te for ts, te in tokens):
                    continue
                matches.append(Match(value_id=c.value_id, variant=variant, start=start, end=end))
        matches.sort(key=lambda m: (m.start, m.end, m.value_id))
        return matches

    def redact(self, text: str) -> str:
        """Replace every matched span with ``[REDACTED:<value_id>]`` (idempotent)."""
        for _ in range(_MAX_PASSES):
            matches = self.find(text)
            if not matches:
                return text
            text = _replace_spans(text, matches)
        return text


def _replace_spans(text: str, matches: list[Match]) -> str:
    groups: list[tuple[int, int, list[str]]] = []
    for m in matches:  # sorted by start
        if groups and m.start < groups[-1][1]:
            start, end, ids = groups[-1]
            if m.value_id not in ids:
                ids.append(m.value_id)
            groups[-1] = (start, max(end, m.end), ids)
        else:
            groups.append((m.start, m.end, [m.value_id]))
    parts: list[str] = []
    cursor = 0
    for start, end, ids in groups:
        parts.append(text[cursor:start])
        parts.extend(f"[REDACTED:{vid}]" for vid in ids)
        cursor = end
    parts.append(text[cursor:])
    return "".join(parts)
