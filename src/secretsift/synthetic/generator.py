"""Deterministic, format-preserving synthetic value generation."""

from __future__ import annotations

import base64
import json

from secretsift.exceptions import ConfigError
from secretsift.models import DataType, SyntheticValue
from secretsift.synthetic.markers import derive_root, make_marker, stream_bytes

_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"  # 32 symbols: byte & 31 is unbiased
_FIRST = ("Alder", "Briar", "Cedar", "Dune", "Ember", "Fenwick", "Garnet", "Hollis")
_LAST = ("Testwright", "Mockridge", "Fakeman", "Dummerson", "Samplefield", "Stubbs")
_JWT_HEADER = '{"alg":"none","typ":"JWT"}'


def _chars(root: bytes, purpose: str, count: int) -> str:
    return "".join(_ALPHABET[b & 31] for b in stream_bytes(root, purpose, count))


def _b64url(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


def _pick(root: bytes, purpose: str, options: tuple[str, ...]) -> str:
    return options[stream_bytes(root, purpose, 1)[0] % len(options)]


def _body(root: bytes, data_type: DataType, marker: str) -> str:
    if data_type is DataType.API_KEY:
        return f"sk-test-{marker}-{_chars(root, 'key', 24)}"
    if data_type is DataType.BEARER_TOKEN:
        payload = json.dumps({"sub": f"synthetic-{marker}", "note": "secretsift-fake"})
        signature = f"{marker}{_chars(root, 'sig', 24)}"
        return f"{_b64url(_JWT_HEADER)}.{_b64url(payload)}.{signature}"
    if data_type is DataType.PASSWORD:
        return f"Tp!{marker}&{_chars(root, 'pw', 8)}#"
    if data_type is DataType.SESSION_ID:
        return f"{marker}{stream_bytes(root, 'sid', 10).hex()}"
    if data_type is DataType.EMAIL:
        return f"user{_chars(root, 'mail', 6)}.{marker}@example.test"
    if data_type is DataType.PHONE:
        line = int.from_bytes(stream_bytes(root, "phone", 1), "big") % 100
        return f"+1-555-01{line:02d}-{marker}"
    if data_type is DataType.NAME:
        return f"{_pick(root, 'first', _FIRST)} {_pick(root, 'last', _LAST)}-{marker}"
    if data_type is DataType.CUSTOMER_ID:
        digits = "".join(str(b % 10) for b in stream_bytes(root, "cust", 4))
        return f"CUST-{marker}-{digits}"
    return f"custom-{marker}-{_chars(root, 'custom', 12)}"


def _type_root(root: bytes, data_type: DataType) -> bytes:
    """Mix the data type into the body stream so types never share random material."""
    return stream_bytes(root, f"type/{data_type.value}", 32)


def generate_value(
    label: str, data_type: DataType, *, run_id: str, seed: int | None
) -> SyntheticValue:
    """Generate one synthetic value. Deterministic for a given seed, run_id and label."""
    if not label or not run_id:
        raise ConfigError("label and run_id must be non-empty")
    try:
        data_type = DataType(data_type)
    except ValueError:
        raise ConfigError(f"unknown synthetic data type: {data_type!r}") from None
    root = derive_root(seed, run_id, label)
    marker = make_marker(root, data_type)
    body_root = _type_root(root, data_type)
    value = _body(body_root, data_type, marker)
    value_id = "sv_" + stream_bytes(root, "id", 4).hex()
    return SyntheticValue(
        id=value_id,
        data_type=data_type,
        label=label,
        value=value,
        marker=marker,
        run_id=run_id,
    )
