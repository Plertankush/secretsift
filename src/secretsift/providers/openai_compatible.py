"""OpenAI-compatible chat completions adapter (``POST {base_url}/chat/completions``).

Wire format implemented from public API docs: request ``{"model", "messages", "stream"}`` with
the system prompt as a leading ``system`` message and ``Authorization: Bearer <key>``; response
``choices[0].message.content``; streaming as SSE ``data:`` lines carrying
``choices[0].delta.content`` and a final ``data: [DONE]``. Verify against current provider docs
before relying on it; it has not been exercised against a live service.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from secretsift.exceptions import ProviderError
from secretsift.providers.base import (
    HttpProvider,
    ProviderRequest,
    ProviderResponse,
    object_list,
)
from secretsift.providers.transport import (
    Transport,
    error_text_from_json,
    parse_json_object,
    sanitize_text,
)


def _content_text(content: object) -> str:
    """Normalize a message/delta content value (string, parts list or null) to text."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            p["text"] for p in content if isinstance(p, dict) and isinstance(p.get("text"), str)
        )
    return ""


class OpenAICompatibleProvider(HttpProvider):
    """Any server speaking the OpenAI chat completions protocol."""

    def __init__(
        self,
        base_url: str,
        *,
        name: str = "openai_compatible",
        api_key_env: str | None = None,
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

    def _headers(self) -> dict[str, str]:
        key = self._api_key()
        return {"Authorization": f"Bearer {key}"} if key else {}

    def _body(self, req: ProviderRequest, stream: bool) -> dict[str, Any]:
        messages: list[dict[str, str]] = []
        if req.system:
            messages.append({"role": "system", "content": req.system})
        messages.extend({"role": m.role, "content": m.content} for m in req.messages)
        body: dict[str, Any] = dict(req.params)
        model = self._model(req)
        if model:
            body["model"] = model
        body["messages"] = messages
        body["stream"] = stream
        return body

    @property
    def _url(self) -> str:
        return f"{self._base_url}/chat/completions"

    def complete(self, req: ProviderRequest) -> ProviderResponse:
        body = self._body(req, False)
        data = self._transport.post_json(self._url, self._headers(), body)
        choices = object_list(data, "choices")
        if not choices:
            raise ProviderError(f"{self.name}: response contained no choices")
        first = choices[0]
        message = first.get("message")
        text = _content_text(message.get("content")) if isinstance(message, dict) else ""
        meta: dict[str, Any] = {}
        for key in ("id", "finish_reason", "usage"):
            value = first.get(key, data.get(key))
            if value is not None:
                meta[key] = value
        return ProviderResponse(
            text=text, model=str(data.get("model") or body.get("model") or ""), metadata=meta
        )

    def stream(self, req: ProviderRequest) -> Iterator[str]:
        body = self._body(req, True)
        for payload in self._transport.stream_sse(self._url, self._headers(), body):
            if payload.strip() == "[DONE]":
                return
            chunk = parse_json_object(payload, f"{self.name} stream event")
            if "error" in chunk:
                detail = sanitize_text(error_text_from_json(chunk) or "unknown error")
                raise ProviderError(f"{self.name}: stream error: {detail}")
            for choice in object_list(chunk, "choices"):
                delta = choice.get("delta")
                text = _content_text(delta.get("content")) if isinstance(delta, dict) else ""
                if text:
                    yield text
