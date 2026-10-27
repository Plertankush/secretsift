"""Storage scanner and in-memory adapter."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from secretsift.core.events import EventCollector
from secretsift.instrumentation import storage
from secretsift.instrumentation.sockets import host_allowed, is_loopback, normalize_allowlist


class ScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name) / "root"
        self.root.mkdir()
        self.outside = Path(self._tmp.name) / "outside.txt"
        self.outside.write_text("OUTSIDE-SECRET")

    def _scan(self) -> EventCollector:
        col = EventCollector()
        storage.scan_paths([self.root], col)
        return col

    def test_text_files_become_events(self) -> None:
        (self.root / "sub").mkdir()
        (self.root / "sub" / "a.txt").write_text("alpha")
        col = self._scan()
        ev = list(col)
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0].metadata["path"], "sub/a.txt")
        self.assertEqual(ev[0].component, "storage:root")
        self.assertEqual(ev[0].payload, "alpha")

    def test_symlink_escape_refused(self) -> None:
        (self.root / "ok.txt").write_text("fine")
        os.symlink(self.outside, self.root / "link.txt")
        os.symlink(self.outside.parent, self.root / "dirlink")
        col = self._scan()
        self.assertNotIn("OUTSIDE-SECRET", "".join(e.payload for e in col))
        self.assertEqual(col.__len__(), 1)
        self.assertEqual(list(col)[0].metadata["skipped"]["symlink"], 2)

    def test_inside_symlink_followed(self) -> None:
        (self.root / "real.txt").write_text("data")
        os.symlink(self.root / "real.txt", self.root / "alias.txt")
        self.assertEqual(len(self._scan()), 2)

    def test_binary_and_large_skipped(self) -> None:
        (self.root / "t.txt").write_text("text")
        (self.root / "b.bin").write_bytes(b"\x00\x01\x02binary")
        (self.root / "big.txt").write_bytes(b"a" * (storage.MAX_FILE_BYTES + 1))
        col = self._scan()
        ev = list(col)
        self.assertEqual([e.metadata["path"] for e in ev], ["t.txt"])
        self.assertEqual(ev[0].metadata["skipped"], {"binary": 1, "too_large": 1})

    def test_missing_and_symlink_root(self) -> None:
        col = EventCollector()
        storage.scan_paths([self.root / "nope"], col)
        self.assertTrue(list(col)[0].metadata["missing"])
        link = Path(self._tmp.name) / "rootlink"
        os.symlink(self.root, link)
        col2 = EventCollector()
        self.assertEqual(storage.scan_paths([link], col2), 0)

    def test_single_file_root(self) -> None:
        col = EventCollector()
        storage.scan_paths([self.outside], col)
        self.assertEqual(list(col)[0].metadata["path"], "outside.txt")

    def test_dict_adapter(self) -> None:
        col = EventCollector()
        n = storage.DictStorageAdapter({"k": "v", 1: {"a": b"x"}}, name="cache").snapshot(col)
        self.assertEqual(n, 2)
        self.assertEqual({e.component for e in col}, {"storage:cache"})
        self.assertIn("k\nv", [e.payload for e in col])


class HostTests(unittest.TestCase):
    def test_loopback(self) -> None:
        for h in ("127.0.0.1", "localhost", "::1", "[::1]", "::ffff:127.0.0.1", "LOCALHOST."):
            self.assertTrue(is_loopback(h), h)
        for h in ("example.com", "10.0.0.1", "127.0.0.1.evil.com", ""):
            self.assertFalse(is_loopback(h), h)

    def test_policy(self) -> None:
        none = frozenset[str]()
        self.assertFalse(host_allowed("example.com", offline=True, allowlist=none))
        self.assertTrue(host_allowed("example.com", offline=False, allowlist=none))
        al = normalize_allowlist(["API.Ok.test", "*.corp.test"])
        self.assertTrue(host_allowed("api.ok.test", offline=False, allowlist=al))
        self.assertTrue(host_allowed("x.corp.test", offline=False, allowlist=al))
        self.assertFalse(host_allowed("corp.test.evil.com", offline=False, allowlist=al))
        self.assertFalse(host_allowed("api.ok.test", offline=True, allowlist=al))


if __name__ == "__main__":
    unittest.main()
