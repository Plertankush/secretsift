"""Safe text handling and file writing shared by every reporter.

``printable`` makes untrusted strings safe for terminals, HTML and XML. ``write_text_atomic``
writes report files without following symlinks and with owner-only permissions.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
import unicodedata
from pathlib import Path

from secretsift.exceptions import SecurityError

_NAMED = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}
# Bidirectional controls can reorder displayed text ("Trojan Source"); show them as escapes.
_BIDI = frozenset("؜‎‏‪‫‬‭‮⁦⁧⁨⁩")
_SEPARATORS = frozenset("  ")


def _is_unsafe(ch: str) -> bool:
    code = ord(ch)
    if ch in _BIDI or ch in _SEPARATORS:
        return True
    if 0xFDD0 <= code <= 0xFDEF or (code & 0xFFFE) == 0xFFFE:
        return True  # noncharacters are not valid in XML 1.0
    return unicodedata.category(ch) in ("Cc", "Cs")


def _escape_char(ch: str) -> str:
    named = _NAMED.get(ch)
    if named is not None:
        return named
    code = ord(ch)
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"


def printable(text: str, *, limit: int | None = None, keep_newlines: bool = False) -> str:
    """Return ``text`` with control, surrogate and bidi characters shown as visible escapes.

    The result is safe to embed in a terminal, HTML or XML 1.0 document. ``limit`` truncates
    overlong input first. With ``keep_newlines`` real newlines and tabs are preserved.
    """
    suffix = ""
    if limit is not None and len(text) > limit:
        suffix = f"... [{len(text) - limit} more characters truncated]"
        text = text[:limit]
    out: list[str] = []
    for ch in text:
        if keep_newlines and ch in "\n\t":
            out.append(ch)
        elif _is_unsafe(ch):
            out.append(_escape_char(ch))
        else:
            out.append(ch)
    return "".join(out) + suffix


def write_text_atomic(path: str | os.PathLike[str], text: str, *, mode: int = 0o600) -> Path:
    """Atomically write UTF-8 ``text`` to ``path`` with permissions ``mode``.

    Parent directories are created. A symlink as the target or as its parent directory is
    refused (``SecurityError``). The data goes to a temp file in the same directory, is synced
    and then renamed over the target, so readers never see a partial report.
    """
    target = Path(path)
    parent = target.parent
    if target.is_symlink() or parent.is_symlink():
        raise SecurityError("refusing to write a report through a symlink")
    if target.exists() and not target.is_file():
        raise SecurityError("report path exists and is not a regular file")
    parent.mkdir(parents=True, exist_ok=True)
    if parent.is_symlink():
        raise SecurityError("refusing to write a report through a symlink")
    fd, tmp_name = tempfile.mkstemp(dir=parent, prefix=f".{target.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise
    return target
