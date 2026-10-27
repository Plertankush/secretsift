"""Explicit-path storage scanning and an in-memory adapter. Never walks outside given roots."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from secretsift.core.events import EventCollector
from secretsift.models import Destination

MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_FILES_PER_ROOT = 10_000
_SNIFF = 8192


@dataclass
class ScanResult:
    """Outcome for one root: scanned files as ``(relative_path, text, size)`` plus skip counts."""

    name: str
    files: list[tuple[str, str, int]] = field(default_factory=list)
    skipped: dict[str, int] = field(
        default_factory=lambda: {
            "binary": 0,
            "too_large": 0,
            "symlink": 0,
            "unreadable": 0,
            "over_limit": 0,
        }
    )
    missing: bool = False


def _looks_binary(sample: bytes) -> bool:
    if b"\0" in sample:
        return True
    if not sample:
        return False
    odd = sum(1 for b in sample if b < 32 and b not in (9, 10, 13))
    return odd / len(sample) > 0.30


def _read(path: Path, result: ScanResult, rel: str) -> None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        result.skipped["unreadable"] += 1
        return
    try:
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                result.skipped["unreadable"] += 1
                return
            if info.st_size > MAX_FILE_BYTES:
                result.skipped["too_large"] += 1
                return
            data = handle.read(MAX_FILE_BYTES + 1)
    except OSError:
        result.skipped["unreadable"] += 1
        return
    if len(data) > MAX_FILE_BYTES:
        result.skipped["too_large"] += 1
    elif _looks_binary(data[:_SNIFF]):
        result.skipped["binary"] += 1
    else:
        result.files.append((rel, data.decode("utf-8", "replace"), len(data)))


def scan_root(root: Path) -> ScanResult:
    """Scan one explicit file or directory without following symlinks out of it."""
    name = root.name or "root"
    result = ScanResult(name=name)
    if not os.path.lexists(root):
        result.missing = True
        return result
    if root.is_symlink():
        result.skipped["symlink"] += 1
        return result
    if root.is_file():
        _read(root, result, root.name)
        return result
    base = root.resolve()
    count = 0
    for current, dirs, files in os.walk(base, followlinks=False):
        dirs.sort()
        for entry in list(dirs):
            if (Path(current) / entry).is_symlink():
                dirs.remove(entry)
                result.skipped["symlink"] += 1
        for filename in sorted(files):
            path = Path(current) / filename
            if count >= MAX_FILES_PER_ROOT:
                result.skipped["over_limit"] += 1
                continue
            count += 1
            target = path
            if path.is_symlink():
                target = path.resolve()
                if not target.is_relative_to(base):
                    result.skipped["symlink"] += 1
                    continue
            _read(target, result, path.relative_to(base).as_posix())
    return result


def scan_paths(paths: Sequence[Path], collector: EventCollector) -> int:
    """Emit one ``storage`` event per scanned file; returns the number of files scanned."""
    total = 0
    for root in paths:
        result = scan_root(Path(root))
        skipped = {k: v for k, v in result.skipped.items() if v}
        component = f"storage:{result.name}"
        for rel, text, size in result.files:
            meta: dict[str, Any] = {"path": rel, "size": size, "skipped": skipped}
            collector.record(Destination.STORAGE, component, text, metadata=meta)
        total += len(result.files)
        if not result.files:
            meta = {"path": ".", "files_scanned": 0, "skipped": skipped, "missing": result.missing}
            collector.record(Destination.STORAGE, component, "", metadata=meta)
    return total


def _as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bytes | bytearray):
        return bytes(value).decode("utf-8", "replace")
    try:
        return json.dumps(value, default=repr, ensure_ascii=False)
    except (TypeError, ValueError):
        return repr(value)


class DictStorageAdapter:
    """Exposes an in-memory mapping (cache, session store) as scannable storage."""

    def __init__(self, mapping: Mapping[Any, Any], name: str = "memory") -> None:
        self._mapping = mapping
        self.name = name

    def entries(self) -> Iterator[tuple[str, str]]:
        """Yield ``(key_text, value_text)`` for a point-in-time copy of the mapping."""
        for key, value in list(self._mapping.items()):
            yield _as_text(key), _as_text(value)

    def snapshot(self, collector: EventCollector) -> int:
        """Emit one ``storage`` event per entry (key and value in the payload)."""
        count = 0
        for index, (key, value) in enumerate(self.entries()):
            collector.record(
                Destination.STORAGE,
                f"storage:{self.name}",
                f"{key}\n{value}",
                metadata={"entry": index},
            )
            count += 1
        return count
