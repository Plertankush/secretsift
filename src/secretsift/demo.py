"""Intentionally leaky and safe demo targets for secretsift's starter config and tests.

Nothing here is meant to be copied into real code: the ``leaky_*`` functions exist so
secretsift has something to catch, and the ``safe_*`` functions show the fixed behavior.
"""

from __future__ import annotations

import logging
from typing import Any

from secretsift.providers.base import Message, ProviderRequest

_log = logging.getLogger("secretsift.demo")


def _ask(provider: Any, content: str) -> str:
    request = ProviderRequest(messages=[Message(role="user", content=content)])
    return str(provider.complete(request).text)


def leaky_login(api_key: str, note: str) -> str:
    """Intentionally leaky demo target for secretsift: logs the API key at INFO."""
    _log.info("login attempt api_key=%s note=%s", api_key, note)
    return "ok"


def safe_login(api_key: str, note: str) -> str:
    """Intentionally safe demo target for secretsift: logs only a masked hint."""
    _log.info("login attempt key=%s*** note=%s", api_key[:3], note)
    return "ok"


def leaky_chat(provider: Any, api_key: str, note: str) -> str:
    """Intentionally leaky demo target for secretsift: sends and prints the API key."""
    print(f"debug: using key {api_key}")
    return _ask(provider, f"api_key={api_key} note={note}")


def safe_chat(provider: Any, api_key: str, note: str) -> str:
    """Intentionally safe demo target for secretsift: sends only the note."""
    del api_key
    return _ask(provider, note)
