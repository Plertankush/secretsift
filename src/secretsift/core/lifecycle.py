"""Guaranteed-cleanup context manager for one scenario run."""

from __future__ import annotations

from collections.abc import Callable
from types import TracebackType

from secretsift.core.context import RunContext
from secretsift.exceptions import ScenarioError


class Lifecycle:
    """Runs registered cleanup steps on exit, always, in a fixed order.

    Order: steps added with :meth:`add` run last-added-first, then the context's collector
    is cleared, then its registry (so raw values are dropped last, after other steps could
    still redact). A failing step never skips the others. A body exception propagates
    unchanged; otherwise cleanup failures raise :class:`ScenarioError` naming the failed
    steps and exception types only (messages could contain sensitive text).
    """

    def __init__(self, context: RunContext | None = None) -> None:
        self.context = context
        self._steps: list[tuple[str, Callable[[], object]]] = []
        self.failed_steps: list[str] = []
        self.completed_steps: list[str] = []

    def add(self, name: str, step: Callable[[], object]) -> None:
        """Register a cleanup step."""
        self._steps.append((name, step))

    def __enter__(self) -> Lifecycle:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        steps = list(reversed(self._steps))
        if self.context is not None:
            steps.append(("collector", self.context.collector.clear))
            steps.append(("registry", self.context.registry.clear))
        errors: list[str] = []
        for name, step in steps:
            try:
                step()
            except Exception as err:
                self.failed_steps.append(name)
                errors.append(f"{name} ({type(err).__name__})")
            else:
                self.completed_steps.append(name)
        if errors and exc_type is None:
            raise ScenarioError("cleanup failed: " + ", ".join(errors))
