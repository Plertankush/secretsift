"""Instrumentation -> default_inspectors end to end (logs, stdout, local HTTP request)."""

from __future__ import annotations

import contextlib
import http.server
import io
import logging
import threading
import unittest
import urllib.request
from collections.abc import Iterator

from secretsift.core.events import EventCollector
from secretsift.inspectors import default_inspectors
from secretsift.instrumentation import Instrumentation
from secretsift.models import DataType, Destination
from secretsift.synthetic.generator import generate_value
from secretsift.synthetic.registry import SecretRegistry


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args: object) -> None:
        return


@contextlib.contextmanager
def local_server() -> Iterator[int]:
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def scan(collector: EventCollector, registry: SecretRegistry) -> dict[str, set[str]]:
    """Map inspector name -> component/part labels with a hit."""
    found: dict[str, set[str]] = {}
    for event in collector:
        for insp in default_inspectors():
            if insp.inspect(event, registry):
                label = str(event.metadata.get("part") or event.component)
                found.setdefault(insp.name, set()).add(label)
    return found


class EndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = SecretRegistry()
        self.sv = generate_value("tok", DataType.BEARER_TOKEN, run_id="r", seed=3)
        self.registry.register(self.sv)

    def _run(self, secret: str) -> dict[str, set[str]]:
        collector = EventCollector()
        sink = io.StringIO()
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(io.StringIO()):
            with Instrumentation(collector, offline=True) as _:
                logging.getLogger("e2e").warning("user token %s", secret)
                print("debug", secret)
                with local_server() as port:
                    req = urllib.request.Request(
                        f"http://127.0.0.1:{port}/p?x=1",
                        data=f"payload={secret}".encode(),
                        headers={"X-Trace": "t"},
                        method="POST",
                    )
                    urllib.request.urlopen(req, timeout=5).read()
        return scan(collector, self.registry)

    def test_planted_secret_found_in_every_channel(self) -> None:
        found = self._run(self.sv.value)
        self.assertIn("e2e", found["logs"])
        self.assertIn("stdout", found["logs"])
        self.assertEqual(found["http"], {"body"})
        self.assertEqual(set(found), {"logs", "http"})

    def test_clean_run_reports_nothing(self) -> None:
        self.assertEqual(self._run("nothing-to-see"), {})

    def test_events_do_not_expose_destinations_outside_run(self) -> None:
        collector = EventCollector()
        with Instrumentation(collector, offline=True):
            logging.getLogger("e2e").info("hello")
        self.assertTrue(all(e.destination == Destination.APPLICATION_LOGS for e in collector))


if __name__ == "__main__":
    unittest.main()
