"""Finds synthetic values persisted to explicit storage paths or caches."""

from __future__ import annotations

from secretsift.inspectors.base import PayloadInspector
from secretsift.models import Destination


class StorageInspector(PayloadInspector):
    """Finds synthetic values persisted to explicit storage paths or caches."""

    def __init__(self) -> None:
        super().__init__("storage", frozenset({Destination.STORAGE}))
