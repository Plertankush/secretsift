"""Log-leak example. Intentionally leaky code: only ever call it with synthetic data."""

from __future__ import annotations

import logging

log = logging.getLogger("log_leak_app")


def mask(secret: str) -> str:
    """Keep a short, non-identifying hint of a secret."""
    return "***" + secret[-2:]


def leaky_login(api_key: str, user: str) -> str:
    """INTENTIONALLY LEAKY: writes the API key to the application log."""
    log.info("login attempt user=%s api_key=%s", user, api_key)
    return "ok"


def fixed_login(api_key: str, user: str) -> str:
    """Fixed: logs who tried to log in and a masked hint, never the key."""
    log.info("login attempt user=%s key_hint=%s", user, mask(api_key))
    return "ok"
