"""llama.cpp server adapter (OpenAI-compatible ``/v1/chat/completions``, no key).

Default base ``http://127.0.0.1:8080/v1``. The model name is optional because the server serves
the model it was started with. Wire format implemented from public docs; verify against the
current llama.cpp server docs before relying on it (no live verification performed).
"""

from __future__ import annotations

from secretsift.providers.openai_compatible import OpenAICompatibleProvider
from secretsift.providers.transport import Transport

DEFAULT_BASE_URL = "http://127.0.0.1:8080/v1"


class LlamaCppProvider(OpenAICompatibleProvider):
    """Local llama.cpp server."""

    model_required = False

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        *,
        name: str = "llama_cpp",
        default_model: str | None = None,
        transport: Transport | None = None,
        timeout: float = 120.0,
    ) -> None:
        super().__init__(
            base_url,
            name=name,
            api_key_env=None,
            default_model=default_model,
            transport=transport,
            timeout=timeout,
        )
