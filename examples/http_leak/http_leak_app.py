"""HTTP-leak example. Intentionally leaky code: only ever call it with synthetic data.

The example starts its own HTTP server on 127.0.0.1 (random port) and calls it, so it needs no
internet access and works with ``offline: true``.
"""

from __future__ import annotations

import contextlib
import http.server
import threading
import urllib.parse
import urllib.request
from collections.abc import Iterator

from secretsift.exceptions import OfflineViolationError


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        """Silence the server's access log: it would write the request URL to stderr."""


@contextlib.contextmanager
def local_server() -> Iterator[str]:
    """Run a throwaway server on 127.0.0.1 and yield its base URL."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _get(url: str, headers: dict[str, str] | None = None) -> str:
    request = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(request, timeout=5) as resp:
        return str(resp.read().decode())


def leaky_lookup(api_key: str) -> str:
    """INTENTIONALLY LEAKY: puts the API key in the URL query string."""
    with local_server() as base:
        return _get(f"{base}/lookup?{urllib.parse.urlencode({'api_key': api_key})}")


def fixed_lookup(api_key: str) -> str:
    """Fixed: the key travels in a header, and the URL carries no secret.

    secretsift masks credential headers (Authorization, X-API-Key, Cookie, ...) before it looks at
    them, so header use is not inspected. See docs/limitations.md.
    """
    with local_server() as base:
        return _get(f"{base}/lookup?q=status", headers={"X-API-Key": api_key})


def blocked_external_call(api_key: str) -> str:
    """Tries a non-loopback host. With offline: true secretsift refuses before any DNS or connect.

    The secret is deliberately not part of the request, so the only thing this scenario shows is
    the offline guard.
    """
    del api_key
    try:
        return _get("http://example.com/health")
    except OfflineViolationError:
        return "blocked by the offline guard"
