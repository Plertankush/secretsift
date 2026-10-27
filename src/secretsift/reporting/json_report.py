"""JSON report: stable schema ``secretsift-report/1`` with strict loading."""

from __future__ import annotations

import json
from typing import Any

from pydantic import ValidationError

from secretsift.contracts import Reporter
from secretsift.exceptions import ConfigError
from secretsift.models import Report

SCHEMA_ID = "secretsift-report/1"
SUPPORTED_SCHEMA_VERSION = "1"
MAX_REPORT_CHARS = 10 * 1024 * 1024


def to_dict(report: Report) -> dict[str, Any]:
    """Return the JSON-ready dict for ``report`` (``$schema`` first)."""
    data: dict[str, Any] = {"$schema": SCHEMA_ID}
    data.update(report.model_dump(mode="json"))
    return data


def dumps(report: Report, *, indent: int | None = 2) -> str:
    """Serialize ``report`` to ASCII-only JSON text (unicode is ``\\u``-escaped)."""
    return json.dumps(to_dict(report), indent=indent, ensure_ascii=True) + "\n"


def loads(text: str) -> Report:
    """Parse and validate a report. Raises ``ConfigError`` without echoing the content."""
    if len(text) > MAX_REPORT_CHARS:
        raise ConfigError(f"report is larger than the {MAX_REPORT_CHARS} character limit")
    try:
        data = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise ConfigError("report is not valid JSON") from exc
    if not isinstance(data, dict):
        raise ConfigError("report must be a JSON object")
    schema = data.pop("$schema", SCHEMA_ID)
    if schema != SCHEMA_ID:
        raise ConfigError("unsupported report $schema (expected " + SCHEMA_ID + ")")
    if data.get("schema_version") != SUPPORTED_SCHEMA_VERSION:
        raise ConfigError(
            "unsupported report schema_version (expected " + SUPPORTED_SCHEMA_VERSION + ")"
        )
    try:
        return Report.model_validate(data)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in err['loc'])}: {err['type']}" for err in exc.errors()[:10]
        )
        raise ConfigError(f"report does not match the schema ({problems})") from exc


class JsonReporter(Reporter):
    """Reporter producing the JSON document."""

    format_name = "json"

    def render(self, report: Report) -> str:
        return dumps(report)
