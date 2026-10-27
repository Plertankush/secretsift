"""UrllibTransport against a local 127.0.0.1 server, plus parser unit tests."""

from __future__ import annotations

import http.server
import json
import threading
import time
import unittest
from collections.abc import Callable
from typing import Any

from secretsift.exceptions import ConfigError, ProviderError
from secretsift.providers.transport import (
    ProviderHTTPError,
    UrllibTransport,
    is_loopback_host,
    iter_ndjson_lines,
    iter_sse_data,
    sanitize_text,
    validate_base_url,
)

SECRET_BODY = {"prompt": "SYNTHETIC-PROMPT-SECRET-123"}
KEY = "sk-live-REALKEY1234567890"
Handler = Callable[[http.server.BaseHTTPRequestHandler, bytes], None]


class _Server:
    def __init__(self, handler: Handler) -> None:
        self.requests: list[tuple[str, dict[str, str], bytes]] = []
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def do_POST(self) -> None:
                n = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(n)
                outer.requests.append((self.path, dict(self.headers), body))
                handler(self, body)

            def log_message(self, *args: Any) -> None:
                return

        class Quiet(http.server.ThreadingHTTPServer):
            def handle_error(self, request: Any, client_address: Any) -> None:
                return  # clients abort on purpose in some tests

        self.httpd = Quiet(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=lambda: self.httpd.serve_forever(0.01), daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(2)


def reply(h: http.server.BaseHTTPRequestHandler, status: int, body: bytes, ctype: str) -> None:
    h.send_response(status)
    h.send_header("Content-Type", ctype)
    h.end_headers()
    h.wfile.write(body)


class ServerCase(unittest.TestCase):
    def serve(self, handler: Handler) -> _Server:
        server = _Server(handler)
        self.addCleanup(server.close)
        return server


class PostJsonTests(ServerCase):
    def test_roundtrip_headers_and_body(self) -> None:
        s = self.serve(lambda h, b: reply(h, 200, b'{"ok": "\xc3\xa9"}', "application/json"))
        out = UrllibTransport().post_json(s.url + "/x?y=1", {"x-api-key": KEY}, {"a": "é"})
        self.assertEqual(out, {"ok": "é"})
        path, headers, body = s.requests[0]
        self.assertEqual(path, "/x?y=1")
        self.assertEqual(headers["x-api-key"], KEY)
        self.assertEqual(json.loads(body.decode()), {"a": "é"})
        self.assertTrue(headers["User-Agent"].startswith("secretsift/"))

    def test_http_error_is_sanitized_and_has_no_request_body(self) -> None:
        err = json.dumps({"error": {"message": f"Incorrect API key provided: {KEY}"}}).encode()
        s = self.serve(lambda h, b: reply(h, 401, err, "application/json"))
        with self.assertRaises(ProviderHTTPError) as cm:
            UrllibTransport().post_json(s.url, {"Authorization": f"Bearer {KEY}"}, SECRET_BODY)
        text = str(cm.exception)
        self.assertEqual(cm.exception.status_code, 401)
        self.assertIn("HTTP 401", text)
        for leaked in ("REALKEY", "SYNTHETIC-PROMPT", "Bearer"):
            self.assertNotIn(leaked, text)

    def test_non_json_and_non_object_responses(self) -> None:
        s = self.serve(lambda h, b: reply(h, 200, b"<html>SECRETPAGE</html>", "text/html"))
        with self.assertRaises(ProviderError) as cm:
            UrllibTransport().post_json(s.url, {}, {})
        self.assertNotIn("SECRETPAGE", str(cm.exception))
        s2 = self.serve(lambda h, b: reply(h, 200, b"[1]", "application/json"))
        with self.assertRaises(ProviderError):
            UrllibTransport().post_json(s2.url, {}, {})

    def test_response_size_cap(self) -> None:
        s = self.serve(
            lambda h, b: reply(h, 200, b'{"a": "' + b"x" * 500 + b'"}', "application/json")
        )
        with self.assertRaises(ProviderError) as cm:
            UrllibTransport(max_response_bytes=100).post_json(s.url, {}, {})
        self.assertIn("size limit", str(cm.exception))

    def test_read_timeout(self) -> None:
        def slow(h: http.server.BaseHTTPRequestHandler, b: bytes) -> None:
            time.sleep(0.4)

        s = self.serve(slow)
        started = time.monotonic()
        with self.assertRaises(ProviderError) as cm:
            UrllibTransport(timeout=0.05).post_json(s.url, {}, SECRET_BODY)
        self.assertIn("timed out", str(cm.exception))
        self.assertLess(time.monotonic() - started, 0.35)

    def test_connection_refused_message_has_no_body(self) -> None:
        s = _Server(lambda h, b: None)
        s.close()
        with self.assertRaises(ProviderError) as cm:
            UrllibTransport(timeout=0.5).post_json(s.url, {}, SECRET_BODY)
        self.assertNotIn("SYNTHETIC-PROMPT", str(cm.exception))

    def test_unserializable_body(self) -> None:
        with self.assertRaises(ProviderError):
            UrllibTransport().post_json("http://127.0.0.1:1", {}, {"a": object()})


class RedirectTests(ServerCase):
    def test_cross_host_redirect_refused(self) -> None:
        target = self.serve(lambda h, b: reply(h, 200, b"{}", "application/json"))

        # "localhost" vs "127.0.0.1": same machine and port, different host => other origin.
        def redirect(h: http.server.BaseHTTPRequestHandler, b: bytes) -> None:
            h.send_response(307)
            h.send_header("Location", f"http://localhost:{target.port}/steal")
            h.end_headers()

        s = self.serve(redirect)
        with self.assertRaises(ProviderError) as cm:
            UrllibTransport().post_json(s.url, {"Authorization": f"Bearer {KEY}"}, SECRET_BODY)
        self.assertIn("another origin", str(cm.exception))
        self.assertEqual(target.requests, [])

    def test_302_not_followed(self) -> None:
        def redirect(h: http.server.BaseHTTPRequestHandler, b: bytes) -> None:
            h.send_response(302)
            h.send_header("Location", "/other")
            h.end_headers()

        s = self.serve(redirect)
        with self.assertRaises(ProviderError) as cm:
            UrllibTransport().post_json(s.url, {}, {})
        self.assertIn("not followed", str(cm.exception))
        self.assertEqual(len(s.requests), 1)

    def test_same_origin_307_followed_with_body(self) -> None:
        def handler(h: http.server.BaseHTTPRequestHandler, b: bytes) -> None:
            if h.path == "/old":
                h.send_response(307)
                h.send_header("Location", "/new")
                h.end_headers()
            else:
                reply(h, 200, b'{"n": 1}', "application/json")

        s = self.serve(handler)
        self.assertEqual(UrllibTransport().post_json(s.url + "/old", {}, {"k": 1}), {"n": 1})
        self.assertEqual([r[0] for r in s.requests], ["/old", "/new"])
        self.assertEqual(json.loads(s.requests[1][2]), {"k": 1})

    def test_redirect_loop_bounded(self) -> None:
        def loop(h: http.server.BaseHTTPRequestHandler, b: bytes) -> None:
            h.send_response(307)
            h.send_header("Location", "/again")
            h.end_headers()

        s = self.serve(loop)
        with self.assertRaises(ProviderError) as cm:
            UrllibTransport(max_redirects=2).post_json(s.url, {}, {})
        self.assertIn("too many redirects", str(cm.exception))
        self.assertEqual(len(s.requests), 3)


class StreamTests(ServerCase):
    def test_sse_partial_writes_split_multibyte_and_crlf(self) -> None:
        event = 'data: {"t": "héllo ✓"}\r\n\r\n'.encode()
        cut = event.index("é".encode()) + 1  # split inside the 2-byte character

        def handler(h: http.server.BaseHTTPRequestHandler, b: bytes) -> None:
            h.send_response(200)
            h.send_header("Content-Type", "text/event-stream")
            h.end_headers()
            for piece in (b": keepalive\n\n", event[:cut], event[cut:], b"data: [DONE]\n\n"):
                h.wfile.write(piece)
                h.wfile.flush()
                time.sleep(0.01)

        s = self.serve(handler)
        out = list(UrllibTransport().stream_sse(s.url, {}, {}))
        self.assertEqual(out, ['{"t": "héllo ✓"}', "[DONE]"])
        self.assertEqual(s.requests[0][1]["Accept"], "text/event-stream")

    def test_ndjson(self) -> None:
        body = b'{"a":1}\n\n{"a":"\xc3\xa9"}\n{"done":true}'
        s = self.serve(lambda h, b: reply(h, 200, body, "application/x-ndjson"))
        out = list(UrllibTransport().stream_ndjson(s.url, {}, {}))
        self.assertEqual(out, ['{"a":1}', '{"a":"é"}', '{"done":true}'])

    def test_stream_http_error_raised_on_first_iteration(self) -> None:
        s = self.serve(lambda h, b: reply(h, 429, b"slow down " + KEY.encode(), "text/plain"))
        with self.assertRaises(ProviderHTTPError) as cm:
            list(UrllibTransport().stream_sse(s.url, {"x-api-key": KEY}, SECRET_BODY))
        self.assertEqual(cm.exception.status_code, 429)
        self.assertNotIn("REALKEY", str(cm.exception))

    def test_line_and_stream_caps(self) -> None:
        s = self.serve(lambda h, b: reply(h, 200, b"data: " + b"x" * 300 + b"\n\n", "text/plain"))
        with self.assertRaises(ProviderError) as cm:
            list(UrllibTransport(max_line_bytes=100).stream_sse(s.url, {}, {}))
        self.assertIn("size limit", str(cm.exception))
        body = b"".join(b"data: " + b"y" * 20 + b"\n\n" for _ in range(20))
        s2 = self.serve(lambda h, b: reply(h, 200, body, "text/plain"))
        with self.assertRaises(ProviderError):
            list(UrllibTransport(max_stream_bytes=100).stream_sse(s2.url, {}, {}))

    def test_stream_idle_timeout_and_total_limit(self) -> None:
        def stall(h: http.server.BaseHTTPRequestHandler, b: bytes) -> None:
            h.send_response(200)
            h.end_headers()
            h.wfile.write(b"data: 1\n\n")
            h.wfile.flush()
            time.sleep(0.4)

        s = self.serve(stall)
        it = UrllibTransport(timeout=0.05).stream_sse(s.url, {}, {})
        self.assertEqual(next(it), "1")
        with self.assertRaises(ProviderError) as cm:
            next(it)
        self.assertIn("timed out", str(cm.exception))

        def drip(h: http.server.BaseHTTPRequestHandler, b: bytes) -> None:
            h.send_response(200)
            h.end_headers()
            for _ in range(5):
                h.wfile.write(b"data: x\n\n")
                h.wfile.flush()
                time.sleep(0.03)

        s2 = self.serve(drip)
        with self.assertRaises(ProviderError) as cm2:
            list(UrllibTransport(total_timeout=0.05).stream_sse(s2.url, {}, {}))
        self.assertIn("total time", str(cm2.exception))


class GuardTests(unittest.TestCase):
    def test_credentials_refused_over_plain_http_non_loopback(self) -> None:
        for header in ("Authorization", "x-api-key", "X-Goog-Api-Key"):
            with self.assertRaises(ProviderError) as cm:
                UrllibTransport().post_json("http://example.invalid/v1", {header: KEY}, {})
            self.assertIn("plain http", str(cm.exception))
            self.assertNotIn("REALKEY", str(cm.exception))

    def test_header_injection_and_bad_scheme(self) -> None:
        with self.assertRaises(ProviderError) as cm:
            UrllibTransport().post_json("http://127.0.0.1:1", {"X-A": "v\r\nEvil: 1"}, {})
        self.assertNotIn("Evil", str(cm.exception))
        with self.assertRaises(ProviderError):
            UrllibTransport().post_json("file:///etc/passwd", {}, {})

    def test_invalid_timeout(self) -> None:
        with self.assertRaises(ConfigError):
            UrllibTransport(timeout=0)


class ParserTests(unittest.TestCase):
    def test_sse_variants(self) -> None:
        lines = [
            "﻿data:no-space\n",
            "\n",
            ": comment\n",
            "event: x\n",
            "id: 4\n",
            "data: a\n",
            "data: b\r\n",
            "\r\n",
            "data: tail",
        ]
        out = list(iter_sse_data(s.encode() for s in lines))
        self.assertEqual(out, ["no-space", "a\nb", "tail"])

    def test_sse_invalid_utf8_replaced(self) -> None:
        self.assertEqual(list(iter_sse_data([b"data: \xff\n", b"\n"])), ["�"])

    def test_ndjson_skips_blank(self) -> None:
        self.assertEqual(list(iter_ndjson_lines([b"\n", b" a \n", b"\r\n", b"b"])), ["a", "b"])

    def test_sanitize_text(self) -> None:
        text = f"Authorization: Bearer {KEY} api_key={KEY} {KEY} Bearer abc123def456\x00\x07 end"
        cleaned = sanitize_text(text)
        self.assertNotIn("REALKEY", cleaned)
        self.assertNotIn("abc123def456", cleaned)
        self.assertNotIn("\x00", cleaned)
        self.assertTrue(sanitize_text("z" * 2000).endswith("..."))
        self.assertLessEqual(len(sanitize_text("z" * 2000)), 503)

    def test_loopback_and_base_url(self) -> None:
        for host in ("localhost", "127.0.0.1", "127.9.9.9", "::1", "[::1]", "LOCALHOST"):
            self.assertTrue(is_loopback_host(host), host)
        for host in ("example.com", "10.0.0.1", "", None, "127.evil.com"):
            self.assertFalse(is_loopback_host(host), host)
        self.assertEqual(validate_base_url(" http://h:80/v1/ "), "http://h:80/v1")
        with self.assertRaises(ConfigError):
            validate_base_url("http://h:notaport/")
        with self.assertRaises(ConfigError):
            validate_base_url(None)


if __name__ == "__main__":
    unittest.main()
