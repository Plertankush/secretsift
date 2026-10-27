"""Exception hierarchy. Messages must never contain raw synthetic values or credentials."""

from __future__ import annotations


class SecretsiftError(Exception):
    """Base class for all secretsift errors."""


class ConfigError(SecretsiftError):
    """Invalid or incomplete configuration, scenario or policy."""


class PolicyError(ConfigError):
    """Policy is malformed, conflicting or references unknown data/destinations."""


class ProviderError(SecretsiftError):
    """An AI provider adapter failed. Message is already credential-redacted."""


class OfflineViolationError(SecretsiftError):
    """A network call was attempted while offline mode was active."""


class SecurityError(SecretsiftError):
    """Unsafe path, unsafe input or other security-boundary violation."""


class ScenarioError(SecretsiftError):
    """A scenario failed to execute (distinct from a privacy finding)."""
