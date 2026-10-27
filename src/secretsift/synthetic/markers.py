"""Marker and deterministic byte-stream helpers (HMAC-SHA256 based, no global RNG state)."""

from __future__ import annotations

import hashlib
import hmac
import secrets

from secretsift.models import DataType

MARKER_HEX_LEN = 12
MARKER_DIGIT_LEN = 8
_DOMAIN = b"secretsift/v1"


def derive_root(seed: int | None, run_id: str, label: str) -> bytes:
    """Derive a 32-byte root key for one (run_id, label). Random when ``seed`` is None."""
    key = secrets.token_bytes(32) if seed is None else _seed_key(seed)
    return hmac.new(key, f"{run_id}\x00{label}".encode(), hashlib.sha256).digest()


def _seed_key(seed: int) -> bytes:
    return hmac.new(_DOMAIN, str(seed).encode(), hashlib.sha256).digest()


def stream_bytes(root: bytes, purpose: str, count: int) -> bytes:
    """Return ``count`` deterministic bytes for ``purpose`` (HMAC in counter mode)."""
    out = bytearray()
    counter = 0
    while len(out) < count:
        msg = purpose.encode() + counter.to_bytes(4, "big")
        out += hmac.new(root, msg, hashlib.sha256).digest()
        counter += 1
    return bytes(out[:count])


def make_marker(root: bytes, data_type: DataType) -> str:
    """Create the per-run marker: 12 lowercase hex chars (8 digits for phone numbers)."""
    if data_type is DataType.PHONE:
        raw = stream_bytes(root, "marker/digits", MARKER_DIGIT_LEN)
        return "".join(str(b % 10) for b in raw)
    return stream_bytes(root, "marker/hex", MARKER_HEX_LEN // 2).hex()
