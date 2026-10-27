"""SecretsiftTransport tests. Pure helpers and event logic run without httpx."""

from __future__ import annotations

import importlib.util
import unittest
from typing import Any

from secretsift.core.events import EventCollector
from secretsift.exceptions import OfflineViolationError, SecretsiftError
from secretsift.integrations import httpx_transport as ht
from secretsift.integrations.httpx_transport import SecretsiftTransport
from secretsift.models import DataType, Destination
from secretsift.synthetic.generator import generate_value
from secretsift.synthetic.registry import SecretRegistry

HAS_HTTPX = importlib.util.find_spec("httpx") is not None


class FakeURL:
    def __init__(self, url: str, host: str) -> None:
        self._url = url
        self.host = host

    def __str__(self) -> str:
        return self._url


class FakeHeaders:
    def __init__(self, items: list[tuple[str, str]]) -> None:
        self._items = items

    def multi_items(self) -> list[tuple[str, str]]:
        return list(self._items)


class FakeRequest:
    def __init__(
        self, url: str, host: str, headers: list[tuple[str, str]], body: bytes = b""
    ) -> None:
        self.method = "POST"
        self.url = FakeURL(url, host)
        self.headers = FakeHeaders(headers)
        self._body = body

    def read(self) -> bytes:
        return self._body


class Wrapped:
    def __init__(self) -> None:
        self.sent: list[Any] = []

    def handle_request(self, request: Any) -> str:
        self.sent.append(request)
        return "response"


def make(**kwargs: Any) -> tuple[SecretsiftTransport, EventCollector, Wrapped]:
    """Build a transport without httpx (bypasses __init__, which needs the dependency)."""
    collector = EventCollector()
    wrapped = Wrapped()
    t = object.__new__(SecretsiftTransport)
    t._wrapped = wrapped
    t._collector = collector
    t._offline = kwargs.get("offline", True)
    t._allowlist = ht.normalize_allowlist(kwargs.get("allowlist", ()))
    t._provider = kwargs.get("provider_name")
    return t, collector, wrapped


class HelperTests(unittest.TestCase):
    def test_sanitized_header_text_redacts_credentials(self) -> None:
        text = ht.sanitized_header_text(
            [("Authorization", "Bearer abc"), ("x-API-key", "k"), ("Accept", "*/*")]
        )
        self.assertEqual(
            text, "Authorization: [HEADER-REDACTED]\nx-API-key: [HEADER-REDACTED]\nAccept: */*"
        )

    def test_decode_body_replaces_invalid_bytes(self) -> None:
        self.assertEqual(ht.decode_body(b"a\xffb"), "a�b")
        self.assertEqual(ht.decode_body("é".encode()), "é")


class ObserveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sv = generate_value("k", DataType.API_KEY, run_id="r", seed=1)
        self.registry = SecretRegistry()
        self.registry.register(self.sv)

    def _events(self, c: EventCollector) -> dict[str, Any]:
        return {e.metadata["part"]: e for e in c}

    def test_loopback_request_emits_three_events(self) -> None:
        t, c, w = make()
        req = FakeRequest(
            "http://127.0.0.1:9/p",
            "127.0.0.1",
            [("Authorization", f"Bearer {self.sv.value}"), ("X-Id", "1")],
            b"hi",
        )
        t.handle_request(req)
        self.assertEqual(w.sent, [req])
        ev = self._events(c)
        self.assertEqual(set(ev), {"url", "headers", "body"})
        self.assertTrue(all(e.destination == Destination.HTTP_REQUEST for e in c))
        self.assertEqual(ev["url"].metadata["method"], "POST")
        self.assertEqual(ev["body"].metadata["bytes"], 2)
        self.assertFalse(ev["body"].approved)
        self.assertNotIn("provider", ev["body"].metadata)
        self.assertIn("[HEADER-REDACTED]", ev["headers"].payload)
        self.assertEqual(self.registry.find(ev["headers"].payload), [])

    def test_provider_name_approves_only_body(self) -> None:
        t, c, _ = make(provider_name="openai")
        t.handle_request(FakeRequest(f"http://localhost/?k={self.sv.value}", "localhost", [], b"b"))
        ev = self._events(c)
        self.assertTrue(ev["body"].approved)
        self.assertEqual(ev["body"].metadata["provider"], "openai")
        self.assertFalse(ev["url"].approved)
        self.assertFalse(ev["headers"].approved)
        self.assertTrue(self.registry.find(ev["url"].payload))

    def test_no_body_event_when_empty(self) -> None:
        t, c, _ = make()
        t.handle_request(FakeRequest("http://localhost/", "localhost", []))
        self.assertEqual(set(self._events(c)), {"url", "headers"})

    def test_offline_blocks_before_sending(self) -> None:
        t, c, w = make(offline=True)
        with self.assertRaises(OfflineViolationError) as ctx:
            t.handle_request(FakeRequest("https://api.example.com/v1", "api.example.com", [], b"x"))
        self.assertEqual(w.sent, [])
        self.assertNotIn("/v1", str(ctx.exception))
        events = list(c)
        self.assertEqual(len(events), 1)
        self.assertTrue(events[0].metadata["blocked"])

    def test_online_allowlist(self) -> None:
        t, c, w = make(offline=False, allowlist=["api.example.com", "*.ok.org"])
        t.handle_request(FakeRequest("https://api.example.com/", "api.example.com", []))
        t.handle_request(FakeRequest("https://a.ok.org/", "a.ok.org", []))
        with self.assertRaises(OfflineViolationError):
            t.handle_request(FakeRequest("https://evil.net/", "evil.net", []))
        self.assertEqual(len(w.sent), 2)

    def test_online_without_allowlist_allows_all(self) -> None:
        t, _, w = make(offline=False)
        t.handle_request(FakeRequest("https://any.example/", "any.example", []))
        self.assertEqual(len(w.sent), 1)


class ConstructionTests(unittest.TestCase):
    @unittest.skipIf(HAS_HTTPX, "httpx installed")
    def test_requires_httpx(self) -> None:
        with self.assertRaises(SecretsiftError):
            SecretsiftTransport(Wrapped(), EventCollector(), offline=True)


@unittest.skipUnless(HAS_HTTPX, "httpx not installed")
class HttpxTests(unittest.TestCase):
    def _client(self, **kwargs: Any) -> tuple[Any, EventCollector, list[Any]]:
        import httpx

        seen: list[Any] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(200, text="ok")

        collector = EventCollector()
        transport = SecretsiftTransport(httpx.MockTransport(handler), collector, **kwargs)
        return httpx.Client(transport=transport), collector, seen

    def test_events_and_redaction(self) -> None:
        client, c, seen = self._client(offline=True, provider_name="p")
        resp = client.post(
            "http://127.0.0.1/x?q=1", content=b"body", headers={"Authorization": "Bearer s"}
        )
        self.assertEqual(resp.text, "ok")
        self.assertEqual(len(seen), 1)
        ev = {e.metadata["part"]: e for e in c}
        self.assertIn("[HEADER-REDACTED]", ev["headers"].payload)
        self.assertNotIn("Bearer s", ev["headers"].payload)
        self.assertEqual(ev["body"].payload, "body")
        self.assertTrue(ev["body"].approved)

    def test_blocked_host_raises_before_send(self) -> None:
        client, _, seen = self._client(offline=True)
        with self.assertRaises(OfflineViolationError):
            client.get("https://api.example.com/")
        self.assertEqual(seen, [])


if __name__ == "__main__":
    unittest.main()
