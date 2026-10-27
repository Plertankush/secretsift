"""Ollama adapter (``POST {base_url}/api/chat``, NDJSON streaming, no key).

Wire format implemented from public API docs: request ``{"model", "messages", "stream",
"options"}`` (``req.params`` is sent as ``options``) with the system prompt as a leading
``system`` message; response ``message.content``; streaming as one JSON object per line
ending with ``"done": true``. Default base ``http://127.0.0.1:11434``. Verify against current
Ollama docs before relying on it (no live verification performed).
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from secretsift.exceptions import ProviderError
from secretsift.providers.base import HttpProvider, ProviderRequest, ProviderResponse
from secretsift.providers.transport import Transport, parse_json_object, sanitize_text

DEFAULT_BASE_URL = "http://127.0.0.1:11434"


class OllamaProvider(HttpProvider):
    """Local Ollama server."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        *,
        name: str = "ollama",
        default_model: str | None = None,
        transport: Transport | None = None,
        timeout: float = 120.0,
    ) -> None:
        super().__init__(
            name=name,
            base_url=base_url,
            api_key_env=None,
            default_model=default_model,
            transport=transport,
            timeout=timeout,
        )

    @property
    def _url(self) -> str:
        return f"{self._base_url}/api/chat"

    def _body(self, req: ProviderRequest, stream: bool) -> dict[str, Any]:
        messages: list[dict[str, str]] = []
        if req.system:
            messages.append({"role": "system", "content": req.system})
        messages.extend({"role": m.role, "content": m.content} for m in req.messages)
        body: dict[str, Any] = {"model": self._model(req), "messages": messages, "stream": stream}
        if req.params:
            body["options"] = dict(req.params)
        return body

    @staticmethod
    def _check_error(data: dict[str, Any]) -> None:
        err = data.get("error")
        if err:
            raise ProviderError(f"ollama: error: {sanitize_text(str(err))}")

    @staticmethod
    def _text(data: dict[str, Any]) -> str:
        message = data.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        return content if isinstance(content, str) else ""

    def complete(self, req: ProviderRequest) -> ProviderResponse:
        body = self._body(req, False)
        data = self._transport.post_json(self._url, {}, body)
        self._check_error(data)
        meta = {k: data[k] for k in ("done_reason", "eval_count", "prompt_eval_count") if k in data}
        return ProviderResponse(
            text=self._text(data), model=str(data.get("model") or body["model"]), metadata=meta
        )

    def stream(self, req: ProviderRequest) -> Iterator[str]:
        body = self._body(req, True)
        for line in self._transport.stream_ndjson(self._url, {}, body):
            data = parse_json_object(line, "ollama stream line")
            self._check_error(data)
            text = self._text(data)
            if text:
                yield text
            if data.get("done") is True:
                return
