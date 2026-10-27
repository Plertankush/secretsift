"""Root-logger handler that records log output as ``application_logs`` events."""

from __future__ import annotations

import logging
import os
import threading
from collections.abc import Callable
from typing import TYPE_CHECKING

from secretsift.models import Destination

if TYPE_CHECKING:
    from secretsift.instrumentation.capture import Instrumentation

_STANDARD = frozenset(logging.makeLogRecord({}).__dict__) | {"message", "asctime", "taskName"}
_FORMATTER = logging.Formatter()


def _render(record: logging.LogRecord) -> str:
    try:
        text = record.getMessage()
    except Exception:
        text = str(record.msg)
        if record.args:
            text += " " + repr(record.args)
    parts = [text]
    if record.exc_info and record.exc_info[0] is not None:
        parts.append(_FORMATTER.formatException(record.exc_info))
    elif record.exc_text:
        parts.append(record.exc_text)
    if record.stack_info:
        parts.append(record.stack_info)
    for key, value in vars(record).items():
        if key not in _STANDARD:
            try:
                parts.append(f"{key}={value}")
            except Exception:
                parts.append(f"{key}=<unprintable>")
    return "\n".join(parts)


class CaptureHandler(logging.Handler):
    """Never logs itself; failures are swallowed so application logging is unaffected."""

    def __init__(self, active: Callable[[], Instrumentation | None]) -> None:
        super().__init__(level=1)
        self._active = active
        self._busy = threading.local()

    def emit(self, record: logging.LogRecord) -> None:
        if getattr(self._busy, "on", False):
            return
        self._busy.on = True
        try:
            inst = self._active()
            if inst is not None:
                inst.record(
                    Destination.APPLICATION_LOGS,
                    record.name,
                    _render(record),
                    metadata={"logger": record.name, "level": record.levelname},
                    location=f"{os.path.basename(record.pathname)}:{record.lineno}",
                )
            self._keep_last_resort(record)
        except Exception:
            return
        finally:
            self._busy.on = False

    def _keep_last_resort(self, record: logging.LogRecord) -> None:
        """Preserve stdlib behavior: with no other handler, warnings still reach stderr."""
        logger: logging.Logger | None = logging.getLogger(record.name)
        while logger is not None:
            if any(h is not self for h in logger.handlers):
                return
            logger = logger.parent if logger.propagate else None
        last = logging.lastResort
        if last is not None and record.levelno >= last.level:
            last.handle(record)


def install(active: Callable[[], Instrumentation | None]) -> Callable[[], None]:
    """Attach the handler to the root logger and lower its level to 1."""
    root = logging.getLogger()
    handler = CaptureHandler(active)
    previous_level = root.level
    root.addHandler(handler)
    root.setLevel(1)

    def restore() -> None:
        root.removeHandler(handler)
        root.setLevel(previous_level)

    return restore
