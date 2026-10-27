"""Inspectors that look for synthetic values in observed events."""

from __future__ import annotations

from secretsift.contracts import Inspector
from secretsift.inspectors.ai_outputs import AIOutputInspector
from secretsift.inspectors.ai_requests import AIRequestInspector
from secretsift.inspectors.base import PayloadInspector
from secretsift.inspectors.errors import ErrorInspector
from secretsift.inspectors.http import HttpInspector
from secretsift.inspectors.logs import LogInspector
from secretsift.inspectors.storage import StorageInspector


def default_inspectors() -> list[Inspector]:
    """One inspector per destination, with stable names."""
    return [
        LogInspector(),
        ErrorInspector(),
        HttpInspector(),
        AIRequestInspector(),
        AIOutputInspector(),
        StorageInspector(),
    ]


__all__ = [
    "AIOutputInspector",
    "AIRequestInspector",
    "ErrorInspector",
    "HttpInspector",
    "LogInspector",
    "PayloadInspector",
    "StorageInspector",
    "default_inspectors",
]
