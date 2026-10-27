"""OpenAI adapter: the OpenAI-compatible protocol with OpenAI defaults.

Default base ``https://api.openai.com/v1`` and key environment variable ``OPENAI_API_KEY``.
Wire format implemented from public API docs; verify against current provider docs before
relying on it (no live verification has been performed).
"""

from __future__ import annotations

from secretsift.providers.openai_compatible import OpenAICompatibleProvider
from secretsift.providers.transport import Transport

DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_KEY_ENV = "OPENAI_API_KEY"


class OpenAIProvider(OpenAICompatibleProvider):
    """OpenAI hosted API."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        *,
        name: str = "openai",
        api_key_env: str = DEFAULT_KEY_ENV,
        default_model: str | None = None,
        transport: Transport | None = None,
        timeout: float = 60.0,
    ) -> None:
        super().__init__(
            base_url,
            name=name,
            api_key_env=api_key_env,
            default_model=default_model,
            transport=transport,
            timeout=timeout,
        )
