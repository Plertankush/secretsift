"""Finds synthetic values in error reports and exception text."""

from __future__ import annotations

from secretsift.inspectors.base import PayloadInspector
from secretsift.models import Destination


class ErrorInspector(PayloadInspector):
    """Finds synthetic values in error reports and exception text."""

    def __init__(self) -> None:
        super().__init__("errors", frozenset({Destination.ERROR_REPORT}))
