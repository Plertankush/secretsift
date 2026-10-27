"""Finds synthetic values in prompts and context sent to an AI model."""

from __future__ import annotations

from secretsift.inspectors.base import PayloadInspector
from secretsift.models import Destination


class AIRequestInspector(PayloadInspector):
    """Finds synthetic values in prompts and context sent to an AI model."""

    def __init__(self) -> None:
        super().__init__("ai_requests", frozenset({Destination.AI_REQUEST}))
