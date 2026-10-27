"""Finds synthetic values in outbound HTTP request URLs, headers and bodies."""

from __future__ import annotations

from secretsift.inspectors.base import PayloadInspector
from secretsift.models import Destination


class HttpInspector(PayloadInspector):
    """Inspects ``http_request`` events (url, headers and body parts carry their text as payload).

    Whether a body is an approved sink is decided by policy from ``event.approved``; this
    inspector reports every occurrence regardless.
    """

    def __init__(self) -> None:
        super().__init__("http", frozenset({Destination.HTTP_REQUEST}))
