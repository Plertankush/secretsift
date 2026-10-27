"""secretsift: local-first privacy leak rehearsal for AI-powered applications."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from secretsift.version import __version__

if TYPE_CHECKING:
    from secretsift.api import Drill

__all__ = ["Drill", "__version__"]


def __getattr__(name: str) -> Any:
    if name == "Drill":
        from secretsift.api import Drill

        return Drill
    raise AttributeError(f"module 'secretsift' has no attribute {name!r}")
