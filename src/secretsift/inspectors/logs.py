"""Finds synthetic values in captured application logs and stdout/stderr."""

from __future__ import annotations

from secretsift.inspectors.base import PayloadInspector
from secretsift.models import Destination


class LogInspector(PayloadInspector):
    """Finds synthetic values in captured application logs and stdout/stderr."""

    def __init__(self) -> None:
        super().__init__("logs", frozenset({Destination.APPLICATION_LOGS}))
