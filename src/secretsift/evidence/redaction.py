"""Redacted evidence snippets and credential masking. Never emits a registered value."""

from __future__ import annotations

import re
from dataclasses import dataclass

from secretsift.contracts import SecretRegistryProtocol
from secretsift.models import Event, Match

MAX_EVIDENCE_CHARS = 240
_ELLIPSIS = "..."
_MASK = "[REDACTED:credential]"
_NOT_MASKED = r"(?!\[REDACTED)"
_TOKEN_CHARS = r"[A-Za-z0-9._~+/=-]"

_AUTHORIZATION = re.compile(
    r"(?i)(\bauthorization[\"']?\s*[:=]\s*[\"']?)(?!(?:[a-z]+\s+)?\[REDACTED)"
    r"((?:bearer|basic|token|digest|apikey)\s+)?[^\s\"',;]+"
)
_BEARER = re.compile(
    r"(?i)\b(bearer\s+)"
    + _NOT_MASKED
    + r"(?="
    + _TOKEN_CHARS
    + r"*[0-9._~+/=-])"
    + _TOKEN_CHARS
    + r"{8,}"
)
_PROVIDER_KEYS = re.compile(
    r"\bsk-(?:[A-Za-z0-9_-]{20,}|(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{8,})"
    r"|\b[spr]k_(?:live|test)_[A-Za-z0-9]{8,}"
    r"|\bAIza[0-9A-Za-z_-]{20,}"
    r"|\bgh[pousr]_[A-Za-z0-9]{20,}"
    r"|\bxox[abprs]-[A-Za-z0-9-]{10,}"
    r"|\bAKIA[0-9A-Z]{16}\b"
    r"|\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"
)
_KEY_NAMES = (
    r"x-goog-api-key|x-api-key|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token"
    r"|id[_-]?token|auth[_-]?token|client[_-]?secret|secret|token|password|passwd"
)
_KEY_VALUE = re.compile(
    r"(?i)(\b(?:" + _KEY_NAMES + r")\b[\"']?\s*[:=]\s*[\"']?)" + _NOT_MASKED + r"[^\s\"'&,;]{4,}"
)
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f  ]")
_ESCAPES = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}


@dataclass
class _Group:
    start: int
    end: int
    ids: list[str]


def redact_text(text: str, registry: SecretRegistryProtocol) -> str:
    """Replace every registered value (and variant) in ``text`` with a redaction token."""
    return registry.redact(text)


def redact_credentials(text: str) -> str:
    """Mask API-key, bearer-token, Authorization and ``api_key=`` style credentials."""
    text = _AUTHORIZATION.sub(lambda m: f"{m.group(1)}{m.group(2) or ''}{_MASK}", text)
    text = _BEARER.sub(lambda m: f"{m.group(1)}{_MASK}", text)
    text = _KEY_VALUE.sub(lambda m: f"{m.group(1)}{_MASK}", text)
    return _PROVIDER_KEYS.sub(_MASK, text)


def _printable(text: str) -> str:
    return _CONTROL.sub(lambda m: _ESCAPES.get(m.group(), f"\\x{ord(m.group()):02x}"), text)


def _groups(payload: str, matches: list[Match], registry: SecretRegistryProtocol) -> list[_Group]:
    """Disjoint spans from the caller's matches plus a fresh scan of the whole payload."""
    ordered = sorted([*matches, *registry.find(payload)], key=lambda m: (m.start, m.end))
    groups: list[_Group] = []
    for m in ordered:
        if groups and m.start < groups[-1].end:
            last = groups[-1]
            last.end = max(last.end, m.end)
            if m.value_id not in last.ids:
                last.ids.append(m.value_id)
        else:
            groups.append(_Group(m.start, m.end, [m.value_id]))
    return groups


def build_evidence(
    event: Event, matches: list[Match], registry: SecretRegistryProtocol, window: int = 40
) -> str:
    """Redacted snippet of ``event.payload`` around the first match (max 240 chars)."""
    payload = event.payload
    window = max(0, window)
    groups = _groups(payload, matches, registry)
    if groups:
        lo = max(0, groups[0].start - window)
        hi = min(len(payload), groups[0].end + window)
    else:
        lo, hi = 0, min(len(payload), 2 * window)
    changed = True
    while changed:  # never cut through a value: widen the window to whole spans
        changed = False
        for g in groups:
            if g.start < lo < g.end:
                lo, changed = g.start, True
            if g.start < hi < g.end:
                hi, changed = g.end, True
    parts: list[str] = []
    cursor = lo
    for g in groups:
        if g.end <= lo or g.start >= hi:
            continue
        parts.append(payload[cursor : g.start])
        parts.extend(f"[REDACTED:{vid}]" for vid in g.ids)
        cursor = g.end
    parts.append(payload[cursor:hi])
    snippet = redact_credentials(_printable(registry.redact("".join(parts))))
    if lo > 0:
        snippet = _ELLIPSIS + snippet
    if hi < len(payload):
        snippet += _ELLIPSIS
    if len(snippet) > MAX_EVIDENCE_CHARS:
        snippet = snippet[: MAX_EVIDENCE_CHARS - len(_ELLIPSIS)] + _ELLIPSIS
    return snippet
