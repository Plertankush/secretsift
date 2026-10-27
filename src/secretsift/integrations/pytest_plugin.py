"""pytest plugin: a ``secretsift`` fixture that fails the test when data leaks.

Loaded automatically through the ``pytest11`` entry point. Mark a test with
``@pytest.mark.secretsift_allow_findings`` to inspect findings without failing it.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from secretsift.api import Drill

MARKER = "secretsift_allow_findings"


def pytest_configure(config: pytest.Config) -> None:
    """Register the opt-out marker."""
    config.addinivalue_line(
        "markers", f"{MARKER}: let the test finish even if the secretsift fixture found leaks"
    )


@pytest.fixture
def secretsift(request: pytest.FixtureRequest) -> Iterator[Drill]:
    """A fresh offline :class:`secretsift.Drill`; fails at teardown if it recorded findings."""
    from secretsift.api import Drill, blocking_message

    drill = Drill(scenario=_scenario_name(request.node.name))
    drill.__enter__()
    try:
        yield drill
    finally:
        drill.__exit__(None, None, None)
    if request.node.get_closest_marker(MARKER) is None:
        message = blocking_message(drill.findings)
        if message is not None:
            pytest.fail(message, pytrace=False)


def _scenario_name(test_name: str) -> str:
    """Scenario-safe name derived from a test id (letters, digits, ``_.-`` and space only)."""
    cleaned = "".join(c if c.isalnum() or c in "_.- " else "_" for c in test_name)
    return cleaned[:100] or "drill"
