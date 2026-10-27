"""Anthropic Messages adapter (``POST {base_url}/messages``).

Default base ``https://api.anthropic.com/v1``.
Wire format implemented from public API docs: headers ``x-api-key`` and
``anthropic-version: 2023-06-01``; body ``{"model", "max_tokens", "system", "messages",
"stream"}`` where the system prompt is the top-level ``system`` string (system-role messages are
merged into it); response ``content`` blocks of ``type: text``; streaming as SSE events whose
``content_block_delta`` carries ``delta.text`` for ``text_delta`` deltas, ending at
``message_stop``. The key is read from ``ANTHROPIC_API_KEY`` at call time only. Verify against
current Anthropic docs before relying on it; it has not been exercised against a live service.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from secretsift.exceptions import ProviderError
from secretsift.providers.base import (
    HttpProvider,
    ProviderRequest,
    ProviderResponse,
    merged_system,
    object_list,
)
from secretsift.providers.transport import (
    Transport,
    error_text_from_json,
    parse_json_object,
    sanitize_text,
)

DEFAULT_BASE_URL = "https://api.anthropic.com/v1"
DEFAULT_KEY_ENV = "ANTHROPIC_API_KEY"
API_VERSION = "2023-06-01"
DEFAULT_MAX_TOKENS = 1024


class AnthropicProvider(HttpProvider):
    """Anthropic hosted Messages API."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        *,
        name: str = "anthropic",
        api_key_env: str = DEFAULT_KEY_ENV,
        default_model: str | None = None,
        transport: Transport | None = None,
        timeout: float = 60.0,
    ) -> None:
        super().__init__(
            name=name,
            base_url=base_url,
            api_key_env=api_key_env,
            default_model=default_model,
            transport=transport,
            timeout=timeout,
        )

    @property
    def _url(self) -> str:
        return f"{self._base_url}/messages"

    def _headers(self) -> dict[str, str]:
        key = self._api_key()
        headers = {"anthropic-version": API_VERSION}
        if key:
            headers["x-api-key"] = key
        return headers

    def _body(self, req: ProviderRequest, stream: bool) -> dict[str, Any]:
        body: dict[str, Any] = {"max_tokens": DEFAULT_MAX_TOKENS}
        body.update(req.params)
        body["model"] = self._model(req)
        system = merged_system(req)
        if system:
            body["system"] = system
        body["messages"] = [
            {"role": m.role, "content": m.content} for m in req.messages if m.role != "system"
        ]
        body["stream"] = stream
        return body

    def complete(self, req: ProviderRequest) -> ProviderResponse:
        body = self._body(req, False)
        data = self._transport.post_json(self._url, self._headers(), body)
        if data.get("type") == "error":
            detail = sanitize_text(error_text_from_json(data) or "unknown error")
            raise ProviderError(f"{self.name}: error: {detail}")
        text = "".join(
            b["text"]
            for b in object_list(data, "content")
            if b.get("type") == "text" and isinstance(b.get("text"), str)
        )
        meta: dict[str, Any] = {}
        for key in ("id", "stop_reason", "usage"):
            if data.get(key) is not None:
                meta[key] = data[key]
        return ProviderResponse(
            text=text, model=str(data.get("model") or body["model"]), metadata=meta
        )

    def stream(self, req: ProviderRequest) -> Iterator[str]:
        body = self._body(req, True)
        for payload in self._transport.stream_sse(self._url, self._headers(), body):
            event = parse_json_object(payload, f"{self.name} stream event")
            kind = event.get("type")
            if kind == "error":
                detail = sanitize_text(error_text_from_json(event) or "unknown error")
                raise ProviderError(f"{self.name}: stream error: {detail}")
            if kind == "message_stop":
                return
            if kind != "content_block_delta":
                continue
            delta = event.get("delta")
            if isinstance(delta, dict) and delta.get("type") == "text_delta":
                text = delta.get("text")
                if isinstance(text, str) and text:
                    yield text
