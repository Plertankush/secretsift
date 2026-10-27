"""stdout/stderr tee: records complete lines while forwarding to the real stream."""

from __future__ import annotations

import sys
import threading
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, Any

from secretsift.models import Destination

if TYPE_CHECKING:
    from secretsift.instrumentation.capture import Instrumentation

_MAX_PENDING = 1_000_000


class Tee:
    """File-like wrapper; unknown attributes are delegated to the wrapped stream."""

    def __init__(
        self,
        stream: Any,
        name: str,
        active: Callable[[], Instrumentation | None],
    ) -> None:
        self._stream = stream
        self._name = name
        self._active = active
        self._pending = ""
        self._lock = threading.Lock()
        self._busy = threading.local()
        self.enabled = True

    def write(self, text: str) -> int:
        written: int = self._stream.write(text)
        if self.enabled and isinstance(text, str):
            self._capture(text)
        return written

    def writelines(self, lines: Iterable[str]) -> None:
        for line in lines:
            self.write(line)

    def flush(self) -> None:
        self._stream.flush()

    def drain(self) -> None:
        """Emit any trailing partial line."""
        with self._lock:
            text, self._pending = self._pending, ""
        self._emit(text)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)

    def _capture(self, text: str) -> None:
        with self._lock:
            self._pending += text
            cut = self._pending.rfind("\n") + 1
            if cut == 0 and len(self._pending) >= _MAX_PENDING:
                cut = len(self._pending)
            chunk, self._pending = self._pending[:cut], self._pending[cut:]
        self._emit(chunk)

    def _emit(self, chunk: str) -> None:
        if not chunk or getattr(self._busy, "on", False):
            return
        self._busy.on = True
        try:
            inst = self._active()
            if inst is not None and inst.capture_stdio:
                inst.record(
                    Destination.APPLICATION_LOGS,
                    self._name,
                    chunk,
                    metadata={"stream": self._name},
                )
        except Exception:
            return
        finally:
            self._busy.on = False


def install(active: Callable[[], Instrumentation | None]) -> Callable[[], None]:
    """Replace ``sys.stdout``/``sys.stderr`` with tees; restore only if still ours."""
    out = Tee(sys.stdout, "stdout", active)
    err = Tee(sys.stderr, "stderr", active)
    original_out, original_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err

    def restore() -> None:
        out.drain()
        err.drain()
        out.enabled = err.enabled = False
        if sys.stdout is out:
            sys.stdout = original_out
        if sys.stderr is err:
            sys.stderr = original_err

    return restore
