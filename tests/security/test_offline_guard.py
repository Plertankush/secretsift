"""Offline guard security properties."""

from __future__ import annotations

import socket
import unittest
import urllib.request

from secretsift.core.events import EventCollector
from secretsift.exceptions import OfflineViolationError
from secretsift.instrumentation import Instrumentation
from secretsift.instrumentation.sockets import blocked_message


class OfflineGuardTests(unittest.TestCase):
    def test_no_network_activity_for_blocked_hosts(self) -> None:
        calls: list[object] = []
        orig = (socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo)
        socket.socket.connect = lambda s, a: calls.append(a)  # type: ignore[method-assign]
        socket.socket.connect_ex = lambda s, a: calls.append(a) or 0  # type: ignore[method-assign]
        socket.getaddrinfo = lambda *a, **k: calls.append(a)  # type: ignore[assignment]
        try:
            with Instrumentation(EventCollector(), offline=True):
                for url in ("http://203.0.113.9/", "http://evil.example/", "http://[2001:db8::1]/"):
                    with self.assertRaises(OfflineViolationError):
                        urllib.request.urlopen(url, timeout=1)
                with socket.socket() as sock:
                    with self.assertRaises(OfflineViolationError):
                        sock.connect(("198.51.100.1", 443))
                    with self.assertRaises(OfflineViolationError):
                        sock.connect_ex(("198.51.100.1", 443))
        finally:
            socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo = orig  # type: ignore
        self.assertEqual(calls, [])

    def test_error_message_never_carries_full_host(self) -> None:
        msg = blocked_message("alice-ssn-123456789.leak.attacker.example.com", offline=True)
        self.assertNotIn("alice", msg)
        self.assertNotIn("123456789", msg)
        self.assertIn("example.com", msg)
        self.assertNotIn("alice", blocked_message("al ice;<x>.evil", offline=True))

    def test_lookalike_loopback_blocked(self) -> None:
        with Instrumentation(EventCollector(), offline=True) as inst:
            for host in ("127.0.0.1.evil.com", "localhost.evil.com", "0.0.0.0", "169.254.169.254"):
                with self.assertRaises(OfflineViolationError):
                    inst.guard_host(host)

    def test_allowlist_cannot_bypass_offline(self) -> None:
        with Instrumentation(EventCollector(), offline=True, network_allowlist=["a.test"]) as i:
            with self.assertRaises(OfflineViolationError):
                i.guard_host("a.test")


if __name__ == "__main__":
    unittest.main()
