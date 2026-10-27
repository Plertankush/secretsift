"""Basic SDK example. Intentionally leaky code: only ever call it with synthetic data."""

from __future__ import annotations

import logging

log = logging.getLogger("my_app")


def leaky_signup(email: str, password: str) -> str:
    """INTENTIONALLY LEAKY: logs the password and prints the email."""
    log.info("signup email=%s password=%s", email, password)
    print(f"welcome {email}")
    return "created"


def fixed_signup(email: str, password: str) -> str:
    """Fixed: logs only that a signup happened."""
    del email, password
    log.info("signup completed")
    return "created"
