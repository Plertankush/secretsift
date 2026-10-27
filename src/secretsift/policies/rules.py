"""Remediation hints per destination."""

from __future__ import annotations

from secretsift.models import Destination

_HINTS: dict[Destination, str] = {
    Destination.APPLICATION_LOGS: (
        "Do not log sensitive values; mask or drop the field before it reaches the logger."
    ),
    Destination.HTTP_REQUEST: (
        "Do not send sensitive values to outbound HTTP endpoints; strip them or use an "
        "approved destination."
    ),
    Destination.ERROR_REPORT: (
        "Redact sensitive values from exception messages and tracebacks before they are raised."
    ),
    Destination.AI_REQUEST: (
        "Remove sensitive values from prompts and context sent to the AI provider."
    ),
    Destination.AI_OUTPUT: (
        "Prevent the model output or response from echoing sensitive values; filter it first."
    ),
    Destination.STORAGE: (
        "Do not persist sensitive values in files or stores; encrypt or omit them."
    ),
    Destination.APPROVED_TEST_INPUT: "This destination is an approved test input; no action.",
}


def remediation_for(destination: Destination | str) -> str:
    """Return a short remediation hint for a destination."""
    try:
        return _HINTS[Destination(destination)]
    except ValueError:
        return "Review where this sensitive value flows and remove it from this destination."
