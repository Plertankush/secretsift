"""Gemini adapter (``generateContent`` / ``streamGenerateContent?alt=sse``).

Wire format implemented from public API docs: ``POST {base}/models/{model}:generateContent``
(default base ``https://generativelanguage.googleapis.com/v1beta``) with header
``x-goog-api-key``; body ``{"contents": [{"role": "user"|"model", "parts": [{"text"}]}],
"systemInstruction": {"parts": [{"text"}]}, "generationConfig": {...}}`` (``req.params`` is sent
as ``generationConfig``); response ``candidates[0].content.parts[].text``; streaming via
``:streamGenerateContent?alt=sse`` where every SSE ``data:`` is a full response chunk. The key is
read from ``GEMINI_API_KEY`` at call time only and is never placed in the URL. Verify against
current Gemini docs before relying on it; it has not been exercised against a live service.
"""

from __future__ import annotations

import re
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

DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
DEFAULT_KEY_ENV = "GEMINI_API_KEY"
_MODEL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _candidate_text(data: dict[str, Any]) -> str:
    candidates = object_list(data, "candidates")
    if not candidates:
        return ""
    content = candidates[0].get("content")
    if not isinstance(content, dict):
        return ""
    parts = object_list(content, "parts")
    return "".join(p["text"] for p in parts if isinstance(p.get("text"), str))


class GeminiProvider(HttpProvider):
    """Google Gemini API."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        *,
        name: str = "gemini",
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

    def _headers(self) -> dict[str, str]:
        key = self._api_key()
        return {"x-goog-api-key": key} if key else {}

    def _model_name(self, req: ProviderRequest) -> str:
        model = self._model(req) or ""
        model = model.removeprefix("models/")
        if not _MODEL_NAME.match(model):
            raise ProviderError(f"{self.name}: invalid model name")
        return model

    def _body(self, req: ProviderRequest) -> dict[str, Any]:
        body: dict[str, Any] = {
            "contents": [
                {
                    "role": "model" if m.role == "assistant" else "user",
                    "parts": [{"text": m.content}],
                }
                for m in req.messages
                if m.role != "system"
            ]
        }
        system = merged_system(req)
        if system:
            body["systemInstruction"] = {"parts": [{"text": system}]}
        if req.params:
            body["generationConfig"] = dict(req.params)
        return body

    def _check(self, data: dict[str, Any]) -> None:
        if "error" in data:
            detail = sanitize_text(error_text_from_json(data) or "unknown error")
            raise ProviderError(f"{self.name}: error: {detail}")
        feedback = data.get("promptFeedback")
        if not object_list(data, "candidates") and isinstance(feedback, dict):
            reason = sanitize_text(str(feedback.get("blockReason", "unknown")), 60)
            raise ProviderError(f"{self.name}: prompt blocked ({reason})")

    def complete(self, req: ProviderRequest) -> ProviderResponse:
        model = self._model_name(req)
        url = f"{self._base_url}/models/{model}:generateContent"
        data = self._transport.post_json(url, self._headers(), self._body(req))
        self._check(data)
        meta: dict[str, Any] = {}
        candidates = object_list(data, "candidates")
        if candidates and candidates[0].get("finishReason") is not None:
            meta["finish_reason"] = candidates[0]["finishReason"]
        if data.get("usageMetadata") is not None:
            meta["usage"] = data["usageMetadata"]
        return ProviderResponse(
            text=_candidate_text(data), model=str(data.get("modelVersion") or model), metadata=meta
        )

    def stream(self, req: ProviderRequest) -> Iterator[str]:
        model = self._model_name(req)
        url = f"{self._base_url}/models/{model}:streamGenerateContent?alt=sse"
        for payload in self._transport.stream_sse(url, self._headers(), self._body(req)):
            data = parse_json_object(payload, f"{self.name} stream event")
            self._check(data)
            text = _candidate_text(data)
            if text:
                yield text
