"""Finds synthetic values in model outputs, including streamed responses."""

from __future__ import annotations

from secretsift.inspectors.base import PayloadInspector
from secretsift.models import Destination


class AIOutputInspector(PayloadInspector):
    """Inspects ``ai_output`` events.

    Streams are emitted as one event per chunk plus one aggregated event
    (``metadata["aggregated"] is True``) holding the whole text, so a value split across chunk
    boundaries is still found in the aggregated event. Duplicate reports of the same leak are
    merged downstream.
    """

    def __init__(self) -> None:
        super().__init__("ai_outputs", frozenset({Destination.AI_OUTPUT}))
