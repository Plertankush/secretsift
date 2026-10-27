"""Instrumentation against a real local HTTP server."""

from __future__ import annotations

import http.client
import http.server
import io
import logging
import socket
import sys
import threading
import unittest
import urllib.request
from contextlib import redirect_stdout

from secretsift.core.events import EventCollector
from secretsift.exceptions import OfflineViolationError
from secretsift.instrumentation import Instrumentation
from secretsift.models import Destination

SECRET = "sk-live-SECRETVALUE123"


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = do_POST

    def log_message(self, *args: object) -> None:
        return None


def _targets() -> dict[str, object]:
    c = http.client.HTTPConnection
    return {
        "putrequest": c.putrequest,
        "putheader": c.putheader,
        "endheaders": c.endheaders,
        "send": c.send,
        "connect": socket.socket.connect,
        "gai": socket.getaddrinfo,
        "stdout": sys.stdout,
        "stderr": sys.stderr,
        "handlers": list(logging.getLogger().handlers),
        "level": logging.getLogger().level,
    }


class InstrumentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        self.col = EventCollector()
        self.before = _targets()

    def tearDown(self) -> None:
        self.assertEqual(self.before, _targets())

    def _post(self, headers: dict[str, str] | None = None, body: bytes = b"hello body") -> None:
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/path?q=1", data=body, headers=headers or {}
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        opener.open(req, timeout=5).read()

    def _parts(self) -> dict[str, list]:
        out: dict[str, list] = {}
        for e in self.col:
            if e.destination == Destination.HTTP_REQUEST:
                out.setdefault(e.metadata["part"], []).append(e)
        return out

    def test_events_and_header_redaction(self) -> None:
        hdrs = {
            "Authorization": f"Bearer {SECRET}",
            "X-Api-Key": SECRET,
            "Cookie": f"s={SECRET}",
            "Proxy-Authorization": SECRET,
            "X-Goog-Api-Key": SECRET,
            "X-Other": "visible",
        }
        with Instrumentation(self.col, offline=True):
            self._post(hdrs)
        parts = self._parts()
        self.assertIn("/path?q=1", parts["url"][0].payload)
        self.assertIn("X-Other: visible", parts["headers"][0].payload)
        self.assertEqual(parts["body"][0].payload, "hello body")
        self.assertFalse(parts["body"][0].approved)
        self.assertEqual(parts["headers"][0].payload.count("[HEADER-REDACTED]"), 5)
        for e in self.col:
            self.assertNotIn(SECRET, e.payload)
            self.assertNotIn(SECRET, str(e.metadata))

    def test_provider_traffic_approves_only_body(self) -> None:
        with Instrumentation(self.col, offline=True) as inst:
            with inst.provider_traffic("fake"):
                self._post()
            self._post()
        bodies = self._parts()["body"]
        self.assertEqual([b.approved for b in bodies], [True, False])
        self.assertEqual(bodies[0].metadata["provider"], "fake")
        for e in self._parts()["url"] + self._parts()["headers"]:
            self.assertFalse(e.approved)

    def test_offline_blocks_before_connect_and_dns(self) -> None:
        attempts: list[object] = []
        orig_connect, orig_gai = socket.socket.connect, socket.getaddrinfo
        socket.socket.connect = lambda s, a: attempts.append(a)  # type: ignore[method-assign]
        socket.getaddrinfo = lambda *a, **k: attempts.append(a)  # type: ignore[assignment]
        try:
            with Instrumentation(self.col, offline=True):
                with self.assertRaises(OfflineViolationError) as ctx:
                    urllib.request.urlopen("http://example.com/x", timeout=1)
                self.assertNotIn("/x", str(ctx.exception))
                with socket.socket() as sock, self.assertRaises(OfflineViolationError):
                    sock.connect(("93.184.216.34", 80))
                with self.assertRaises(OfflineViolationError):
                    socket.getaddrinfo("example.org", 80)
        finally:
            socket.socket.connect, socket.getaddrinfo = orig_connect, orig_gai  # type: ignore
        self.assertEqual(attempts, [])
        blocked = [e for e in self.col if e.metadata.get("blocked")]
        self.assertEqual(len(blocked), 1)

    def test_allowlist_mode(self) -> None:
        with Instrumentation(self.col, offline=False, network_allowlist=["api.ok.test"]) as inst:
            self._post()  # loopback always allowed
            inst.guard_host("api.ok.test")
            with self.assertRaises(OfflineViolationError):
                inst.guard_host("evil.test")
        with Instrumentation(self.col, offline=False, network_allowlist=["*.ok.test"]) as inst:
            inst.guard_host("a.ok.test")
        with Instrumentation(self.col, offline=False) as inst:
            inst.guard_host("anything.test")

    def test_restore_after_exception_and_nesting(self) -> None:
        with self.assertRaises(RuntimeError):
            with Instrumentation(self.col, offline=True):
                raise RuntimeError("boom")
        self.assertEqual(self.before, _targets())
        with Instrumentation(self.col, offline=True) as outer:
            patched = http.client.HTTPConnection.send
            with Instrumentation(self.col, offline=True) as inner:
                self.assertIs(http.client.HTTPConnection.send, patched)
                with inner:
                    pass
                self.assertIs(http.client.HTTPConnection.send, patched)
            self.assertIs(http.client.HTTPConnection.send, patched)
            self.assertIsNot(outer, inner)
            self._post()
        self.assertEqual(self.before, _targets())

    def test_non_lifo_exit_restores(self) -> None:
        a, b = Instrumentation(self.col, offline=True), Instrumentation(self.col, offline=True)
        a.__enter__()
        b.__enter__()
        a.__exit__(None, None, None)
        self.assertIsNot(http.client.HTTPConnection.send, self.before["send"])
        b.__exit__(None, None, None)

    def test_logging_capture(self) -> None:
        log = logging.getLogger("my.app")
        with Instrumentation(self.col, offline=True):
            log.warning("user %s logged in", "alice")
            try:
                raise ValueError("bad-thing")
            except ValueError:
                log.exception("failed", extra={"email": "a@b.test"})
        logs = [e for e in self.col if e.component == "my.app"]
        self.assertEqual(len(logs), 2)
        self.assertIn("user alice logged in", logs[0].payload)
        self.assertRegex(logs[0].location or "", r"test_capture\.py:\d+")
        self.assertIn("bad-thing", logs[1].payload)
        self.assertIn("email=a@b.test", logs[1].payload)
        # handler must not have produced extra events of its own
        self.assertEqual(len([e for e in self.col if e.component.startswith("secretsift")]), 0)

    def test_stdio_tee_forwards_and_captures(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            with Instrumentation(self.col, offline=True):
                print("line one")
                sys.stdout.write("partial")
                print("to stderr", file=sys.stderr)
        self.assertEqual(buf.getvalue(), "line one\npartial")
        out = [e.payload for e in self.col if e.component == "stdout"]
        self.assertEqual("".join(out), "line one\npartial")
        self.assertTrue(any(e.component == "stderr" for e in self.col))

    def test_capture_stdio_false(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            with Instrumentation(self.col, offline=True, capture_stdio=False):
                print("quiet")
        self.assertEqual(buf.getvalue(), "quiet\n")
        self.assertFalse([e for e in self.col if e.component == "stdout"])

    def test_payload_truncation(self) -> None:
        col = EventCollector(max_payload_chars=10)
        with Instrumentation(col, offline=True):
            self._post(body=b"x" * 50)
        body = [e for e in col if e.metadata.get("part") == "body"][0]
        self.assertEqual(len(body.payload), 10)
        self.assertTrue(body.metadata["truncated"])

    def test_thread_safety(self) -> None:
        errors: list[BaseException] = []

        def work() -> None:
            try:
                for _ in range(5):
                    with Instrumentation(self.col, offline=True):
                        self._post()
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=work) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(self.before, _targets())

    def test_snapshot_storage(self) -> None:
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.txt").write_text("hello")
            with Instrumentation(self.col, offline=True, storage_paths=[Path(d)]) as inst:
                inst.snapshot_storage()
        ev = [e for e in self.col if e.destination == Destination.STORAGE]
        self.assertEqual(ev[0].metadata["path"], "a.txt")


if __name__ == "__main__":
    unittest.main()
