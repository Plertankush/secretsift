"""Adapter wire-format tests (FakeTransport only; no network)."""

from __future__ import annotations

import json
import os
import unittest
from unittest import mock

from secretsift.exceptions import ConfigError, ProviderError
from secretsift.providers import (
    AnthropicProvider,
    GeminiProvider,
    LlamaCppProvider,
    Message,
    OllamaProvider,
    OpenAICompatibleProvider,
    OpenAIProvider,
    ProviderRequest,
)
from tests.unit.providers.fakes import FakeTransport

KEY = "sk-live-REALKEY1234567890"


def request(**kw: object) -> ProviderRequest:
    base: dict[str, object] = {
        "messages": [Message(role="user", content="hi ünï")],
        "model": "m1",
        "system": "be nice",
    }
    base.update(kw)
    return ProviderRequest(**base)  # type: ignore[arg-type]


def sse(*objs: object) -> list[str]:
    return [o if isinstance(o, str) else json.dumps(o) for o in objs]


class OpenAIFamilyTests(unittest.TestCase):
    def test_openai_complete_wire_format(self) -> None:
        t = FakeTransport(
            {"model": "m1-x", "choices": [{"message": {"content": "yo"}, "finish_reason": "stop"}]}
        )
        p = OpenAIProvider(transport=t)
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": KEY}):
            resp = p.complete(request(params={"temperature": 0}))
        kind, url, headers, body = t.calls[0]
        self.assertEqual(url, "https://api.openai.com/v1/chat/completions")
        self.assertEqual(headers, {"Authorization": f"Bearer {KEY}"})
        self.assertEqual(body["messages"][0], {"role": "system", "content": "be nice"})
        self.assertEqual(body["messages"][1], {"role": "user", "content": "hi ünï"})
        self.assertEqual((body["model"], body["stream"], body["temperature"]), ("m1", False, 0))
        self.assertEqual(resp.text, "yo")
        self.assertEqual(resp.model, "m1-x")
        self.assertEqual(resp.metadata["finish_reason"], "stop")

    def test_missing_key_error_names_variable_only(self) -> None:
        p = OpenAIProvider(transport=FakeTransport())
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ProviderError) as cm:
                p.complete(request())
        self.assertIn("OPENAI_API_KEY", str(cm.exception))

    def test_no_choices_and_null_content(self) -> None:
        with self.assertRaises(ProviderError):
            LlamaCppProvider(transport=FakeTransport({"choices": []})).complete(request())
        t = FakeTransport({"choices": [{"message": {"content": None}}]})
        self.assertEqual(LlamaCppProvider(transport=t).complete(request()).text, "")

    def test_stream_partial_done_empty_unicode(self) -> None:
        events = sse(
            {"choices": [{"delta": {"role": "assistant"}}]},
            {"choices": [{"delta": {"content": ""}}]},
            {"choices": [{"delta": {"content": "héllo "}}]},
            {"choices": []},
            {"choices": [{"delta": {"content": "wörld ✓"}}]},
            "[DONE]",
            {"choices": [{"delta": {"content": "after-done"}}]},
        )
        t = FakeTransport(events=events)
        p = OpenAICompatibleProvider("http://127.0.0.1:1/v1", transport=t)
        self.assertEqual(list(p.stream(request())), ["héllo ", "wörld ✓"])
        self.assertTrue(t.calls[0][3]["stream"])
        self.assertEqual(t.calls[0][1], "http://127.0.0.1:1/v1/chat/completions")

    def test_stream_error_event_is_redacted(self) -> None:
        t = FakeTransport(events=sse({"error": {"message": f"bad key {KEY}"}}))
        p = LlamaCppProvider(transport=t)
        with self.assertRaises(ProviderError) as cm:
            list(p.stream(request()))
        self.assertNotIn("REALKEY", str(cm.exception))

    def test_stream_invalid_json_does_not_echo_payload(self) -> None:
        p = LlamaCppProvider(transport=FakeTransport(events=["not json SECRETVALUE"]))
        with self.assertRaises(ProviderError) as cm:
            list(p.stream(request()))
        self.assertNotIn("SECRETVALUE", str(cm.exception))

    def test_llama_cpp_defaults_no_key_no_model(self) -> None:
        t = FakeTransport({"choices": [{"message": {"content": "x"}}]})
        p = LlamaCppProvider(transport=t)
        p.complete(request(model=None))
        _, url, headers, body = t.calls[0]
        self.assertEqual(url, "http://127.0.0.1:8080/v1/chat/completions")
        self.assertEqual(headers, {})
        self.assertNotIn("model", body)
        self.assertFalse(p.requires_network)
        self.assertTrue(p.status().configured)

    def test_model_required_for_openai(self) -> None:
        p = OpenAIProvider(transport=FakeTransport())
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": KEY}):
            with self.assertRaises(ProviderError):
                p.complete(request(model=None))

    def test_default_model_used(self) -> None:
        t = FakeTransport({"choices": [{"message": {"content": "x"}}]})
        p = OpenAIProvider(default_model="dflt", transport=t)
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": KEY}):
            p.complete(request(model=None))
        self.assertEqual(t.calls[0][3]["model"], "dflt")

    def test_content_parts_list(self) -> None:
        data = {"choices": [{"message": {"content": [{"text": "a"}, {"text": "b"}, {"x": 1}]}}]}
        p = LlamaCppProvider(transport=FakeTransport(data))
        self.assertEqual(p.complete(request()).text, "ab")


class OllamaTests(unittest.TestCase):
    def test_complete(self) -> None:
        t = FakeTransport({"model": "llama", "message": {"content": "ok"}, "done_reason": "stop"})
        p = OllamaProvider(transport=t)
        resp = p.complete(request(params={"temperature": 0.1}))
        _, url, headers, body = t.calls[0]
        self.assertEqual(url, "http://127.0.0.1:11434/api/chat")
        self.assertEqual(headers, {})
        self.assertEqual(body["messages"][0], {"role": "system", "content": "be nice"})
        self.assertEqual(body["options"], {"temperature": 0.1})
        self.assertIs(body["stream"], False)
        self.assertEqual((resp.text, resp.model), ("ok", "llama"))

    def test_stream_ndjson(self) -> None:
        events = sse(
            {"message": {"content": "né"}, "done": False},
            {"message": {"content": ""}, "done": False},
            {"message": {"content": "xt"}, "done": False},
            {"message": {"content": ""}, "done": True},
            {"message": {"content": "never"}, "done": False},
        )
        t = FakeTransport(events=events)
        self.assertEqual(list(OllamaProvider(transport=t).stream(request())), ["né", "xt"])
        self.assertEqual(t.calls[0][0], "ndjson")
        self.assertIs(t.calls[0][3]["stream"], True)

    def test_error_field(self) -> None:
        p = OllamaProvider(transport=FakeTransport({"error": f"model failed {KEY}"}))
        with self.assertRaises(ProviderError) as cm:
            p.complete(request())
        self.assertNotIn("REALKEY", str(cm.exception))

    def test_model_required(self) -> None:
        with self.assertRaises(ProviderError):
            OllamaProvider(transport=FakeTransport()).complete(request(model=None))


class AnthropicTests(unittest.TestCase):
    def test_complete_wire_format(self) -> None:
        t = FakeTransport(
            {
                "id": "msg_1",
                "model": "claude-x",
                "content": [
                    {"type": "text", "text": "a"},
                    {"type": "tool_use"},
                    {"type": "text", "text": "b"},
                ],
                "stop_reason": "end_turn",
            }
        )
        msgs = [
            Message(role="system", content="extra sys"),
            Message(role="user", content="q"),
            Message(role="assistant", content="a"),
        ]
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": KEY}):
            resp = AnthropicProvider(transport=t).complete(request(messages=msgs))
        _, url, headers, body = t.calls[0]
        self.assertEqual(url, "https://api.anthropic.com/v1/messages")
        self.assertEqual(headers, {"anthropic-version": "2023-06-01", "x-api-key": KEY})
        self.assertEqual(body["system"], "be nice\n\nextra sys")
        self.assertEqual([m["role"] for m in body["messages"]], ["user", "assistant"])
        self.assertEqual(body["max_tokens"], 1024)
        self.assertEqual(resp.text, "ab")
        self.assertEqual(resp.metadata["stop_reason"], "end_turn")

    def test_no_system_omits_field_and_max_tokens_override(self) -> None:
        t = FakeTransport({"content": []})
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": KEY}):
            AnthropicProvider(transport=t).complete(request(system=None, params={"max_tokens": 7}))
        body = t.calls[0][3]
        self.assertNotIn("system", body)
        self.assertEqual(body["max_tokens"], 7)

    def test_stream_text_deltas(self) -> None:
        events = sse(
            {"type": "message_start", "message": {}},
            {"type": "content_block_start", "index": 0, "content_block": {"type": "text"}},
            '{"type": "ping"}',
            {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "Hel"}},
            {"type": "content_block_delta", "delta": {"type": "text_delta", "text": ""}},
            {
                "type": "content_block_delta",
                "delta": {"type": "input_json_delta", "partial_json": "{"},
            },
            {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "lö ✓"}},
            {"type": "message_stop"},
            {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "late"}},
        )
        t = FakeTransport(events=events)
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": KEY}):
            out = list(AnthropicProvider(transport=t).stream(request()))
        self.assertEqual(out, ["Hel", "lö ✓"])
        self.assertTrue(t.calls[0][3]["stream"])

    def test_stream_error_event(self) -> None:
        events = sse({"type": "error", "error": {"type": "overloaded_error", "message": "busy"}})
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": KEY}):
            with self.assertRaises(ProviderError) as cm:
                list(AnthropicProvider(transport=FakeTransport(events=events)).stream(request()))
        self.assertIn("busy", str(cm.exception))

    def test_status_never_reveals_key(self) -> None:
        p = AnthropicProvider(transport=FakeTransport())
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": KEY}):
            status = p.status()
            shown = repr(p) + repr(status) + status.model_dump_json()
        self.assertTrue(status.configured)
        self.assertNotIn("REALKEY", shown)
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertFalse(p.status().configured)


class GeminiTests(unittest.TestCase):
    def test_complete_wire_format(self) -> None:
        t = FakeTransport(
            {
                "candidates": [
                    {"content": {"parts": [{"text": "x"}, {"text": "y"}]}, "finishReason": "STOP"}
                ],
                "usageMetadata": {"totalTokenCount": 3},
            }
        )
        msgs = [
            Message(role="user", content="q"),
            Message(role="assistant", content="a"),
            Message(role="user", content="q2"),
        ]
        with mock.patch.dict(os.environ, {"GEMINI_API_KEY": KEY}):
            resp = GeminiProvider(transport=t).complete(
                request(messages=msgs, model="models/gem-1", params={"temperature": 0})
            )
        _, url, headers, body = t.calls[0]
        self.assertEqual(
            url,
            "https://generativelanguage.googleapis.com/v1beta/models/gem-1:generateContent",
        )
        self.assertEqual(headers, {"x-goog-api-key": KEY})
        self.assertNotIn(KEY, url)
        self.assertEqual(body["systemInstruction"], {"parts": [{"text": "be nice"}]})
        self.assertEqual([c["role"] for c in body["contents"]], ["user", "model", "user"])
        self.assertEqual(body["contents"][0]["parts"], [{"text": "q"}])
        self.assertEqual(body["generationConfig"], {"temperature": 0})
        self.assertEqual(resp.text, "xy")
        self.assertEqual(resp.metadata["finish_reason"], "STOP")

    def test_stream_url_and_chunks(self) -> None:
        events = sse(
            {"candidates": [{"content": {"parts": [{"text": "ab"}]}}]},
            {"candidates": [{"content": {"parts": [{"text": ""}]}}]},
            {"candidates": [{"content": {"parts": [{"text": "çd"}]}, "finishReason": "STOP"}]},
        )
        t = FakeTransport(events=events)
        with mock.patch.dict(os.environ, {"GEMINI_API_KEY": KEY}):
            out = list(GeminiProvider(transport=t).stream(request(model="gem-1")))
        self.assertEqual(out, ["ab", "çd"])
        self.assertTrue(t.calls[0][1].endswith("/models/gem-1:streamGenerateContent?alt=sse"))
        self.assertEqual(t.calls[0][2], {"x-goog-api-key": KEY})

    def test_invalid_model_name_rejected(self) -> None:
        with mock.patch.dict(os.environ, {"GEMINI_API_KEY": KEY}):
            for bad in ("../x", "a:b", "a/b", "a b"):
                with self.assertRaises(ProviderError):
                    GeminiProvider(transport=FakeTransport()).complete(request(model=bad))

    def test_blocked_prompt_and_error(self) -> None:
        with mock.patch.dict(os.environ, {"GEMINI_API_KEY": KEY}):
            blocked = FakeTransport({"promptFeedback": {"blockReason": "SAFETY"}})
            with self.assertRaises(ProviderError) as cm:
                GeminiProvider(transport=blocked).complete(request())
            self.assertIn("SAFETY", str(cm.exception))
            err = FakeTransport({"error": {"message": f"key {KEY} invalid"}})
            with self.assertRaises(ProviderError) as cm2:
                GeminiProvider(transport=err).complete(request())
            self.assertNotIn("REALKEY", str(cm2.exception))


class SecretHygieneTests(unittest.TestCase):
    def test_keys_absent_from_repr_and_dump(self) -> None:
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": KEY}):
            p = OpenAIProvider(
                transport=FakeTransport({"choices": [{"message": {"content": "o"}}]})
            )
            resp = p.complete(request())
            shown = repr(p) + repr(resp) + resp.model_dump_json() + repr(p.status())
        self.assertNotIn("REALKEY", shown)
        self.assertNotIn("hi ünï", repr(request()) + request().model_dump_json())
        self.assertNotIn("yo", repr(resp))

    def test_inline_secret_as_env_name_rejected(self) -> None:
        with self.assertRaises(ConfigError) as cm:
            OpenAIProvider(api_key_env="sk-abcdef123456-xyz")
        self.assertNotIn("abcdef", str(cm.exception))

    def test_base_url_validation(self) -> None:
        for bad in ("", "ftp://x", "http://u:p@host/v1", "http://h/v1?key=1", "nohost"):
            with self.assertRaises(ConfigError):
                OpenAICompatibleProvider(bad)

    def test_requires_network_flag(self) -> None:
        self.assertTrue(OpenAIProvider(transport=FakeTransport()).requires_network)
        self.assertFalse(OpenAICompatibleProvider("http://localhost:9/v1").requires_network)


if __name__ == "__main__":
    unittest.main()
