from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path

from secretsift.exceptions import ConfigError, SecurityError
from secretsift.reporting import get_reporter, write_report
from secretsift.reporting.safe_io import printable, write_text_atomic
from tests.unit.reporting._fixtures import make_report


class PrintableTests(unittest.TestCase):
    def test_escapes_controls_and_bidi(self) -> None:
        self.assertEqual(printable("a\x00b\x1bc\nd"), "a\\x00b\\x1bc\\nd")
        self.assertEqual(printable("‮ "), "\\u202e\\u2028")
        self.assertEqual(printable("\ud800"), "\\ud800")
        self.assertEqual(printable("￾"), "\\ufffe")

    def test_keeps_unicode_text(self) -> None:
        self.assertEqual(printable("café 中文"), "café 中文")

    def test_keep_newlines_and_limit(self) -> None:
        self.assertEqual(printable("a\nb\tc", keep_newlines=True), "a\nb\tc")
        out = printable("x" * 50, limit=10)
        self.assertTrue(out.startswith("x" * 10 + "..."))
        self.assertIn("40 more", out)


class WriteTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    @unittest.skipIf(os.name == "nt", "POSIX file modes do not exist on Windows")
    def test_creates_parents_with_mode_600(self) -> None:
        target = self.root / "a" / "b" / "r.json"
        out = write_report(make_report(), "json", target)
        self.assertEqual(out, target)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertIn("secretsift-report/1", target.read_text(encoding="utf-8"))

    def test_overwrite_is_atomic_and_leaves_no_temp(self) -> None:
        target = self.root / "r.txt"
        write_text_atomic(target, "one")
        write_text_atomic(target, "two")
        self.assertEqual(target.read_text(), "two")
        self.assertEqual([p.name for p in self.root.iterdir()], ["r.txt"])

    @unittest.skipIf(os.name == "nt", "POSIX file modes do not exist on Windows")
    def test_overwrite_resets_loose_mode(self) -> None:
        target = self.root / "r.txt"
        target.write_text("x")
        os.chmod(target, 0o666)
        write_text_atomic(target, "y")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_refuses_symlink_target(self) -> None:
        victim = self.root / "victim.txt"
        victim.write_text("keep")
        link = self.root / "link.txt"
        link.symlink_to(victim)
        with self.assertRaises(SecurityError):
            write_text_atomic(link, "evil")
        self.assertEqual(victim.read_text(), "keep")

    def test_refuses_symlink_parent(self) -> None:
        real = self.root / "real"
        real.mkdir()
        link = self.root / "linkdir"
        link.symlink_to(real, target_is_directory=True)
        with self.assertRaises(SecurityError):
            write_text_atomic(link / "r.txt", "evil")
        self.assertEqual(list(real.iterdir()), [])

    def test_refuses_directory_target(self) -> None:
        (self.root / "d").mkdir()
        with self.assertRaises(SecurityError):
            write_text_atomic(self.root / "d", "x")

    def test_failure_cleans_temp_file(self) -> None:
        with self.assertRaises(UnicodeEncodeError):
            write_text_atomic(self.root / "r.txt", "\ud800")
        self.assertEqual(list(self.root.iterdir()), [])

    def test_unknown_format(self) -> None:
        with self.assertRaises(ConfigError):
            get_reporter("pdf")

    def test_all_formats_write(self) -> None:
        for fmt in ("terminal", "json", "html", "junit"):
            path = write_report(make_report(), fmt, self.root / f"out.{fmt}")
            self.assertTrue(path.read_text(encoding="utf-8"))
