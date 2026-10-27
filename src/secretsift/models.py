"""Shared typed data model. Every module codes against these types.

Safety rule: raw synthetic values and raw observed payloads are held in memory only.
They are declared ``exclude=True, repr=False`` so ``model_dump`` / ``repr`` never leak them.
"""

from __future__ import annotations

import datetime as dt
import enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Destination(enum.StrEnum):
    """Where an observed piece of data surfaced."""

    APPLICATION_LOGS = "application_logs"
    HTTP_REQUEST = "http_request"
    ERROR_REPORT = "error_report"
    AI_REQUEST = "ai_request"
    AI_OUTPUT = "ai_output"
    STORAGE = "storage"
    APPROVED_TEST_INPUT = "approved_test_input"


WILDCARD = "*"


class DataType(enum.StrEnum):
    API_KEY = "synthetic_api_key"
    BEARER_TOKEN = "synthetic_bearer_token"
    PASSWORD = "synthetic_password"
    SESSION_ID = "synthetic_session_id"
    EMAIL = "synthetic_email"
    PHONE = "synthetic_phone"
    NAME = "synthetic_name"
    CUSTOMER_ID = "synthetic_customer_id"
    CUSTOM = "synthetic_custom"


class Action(enum.StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    WARN = "warn"


class Severity(enum.StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Category(enum.StrEnum):
    """Privacy failure taxonomy (blueprint section 3)."""

    LOGGING = "logging"
    NETWORK = "network"
    AI_CONTEXT = "ai_context"
    RESPONSE = "response"
    STORAGE = "storage"
    REGRESSION = "regression"


class Variant(enum.StrEnum):
    """How a synthetic value was matched inside an observed payload."""

    RAW = "raw"
    CASEFOLD = "casefold"
    URL_ENCODED = "url_encoded"
    BASE64 = "base64"
    HEX = "hex"
    JSON_ESCAPED = "json_escaped"
    WHITESPACE_STRIPPED = "whitespace_stripped"


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class SyntheticValue(_Frozen):
    """A test-only sensitive value. ``value`` is never serialized or repr'd."""

    id: str  # stable id like "sv_3f9a1c"; safe to print
    data_type: DataType
    label: str  # human label, e.g. "customer_api_key"; safe to print
    value: str = Field(repr=False, exclude=True)
    marker: str  # unique per-run substring embedded in value; safe to print only as its id
    run_id: str


class Event(_Frozen):
    """One normalized observation emitted by instrumentation."""

    id: str
    destination: Destination
    component: str  # e.g. "app.auth", "httpx", "provider.openai"
    timestamp: dt.datetime
    payload: str = Field(repr=False, exclude=True)  # raw observed text, memory only
    metadata: dict[str, Any] = Field(default_factory=dict)  # must contain no raw secrets
    location: str | None = None  # "file.py:42" if known, else None
    approved: bool = False  # True when the destination is an explicitly approved sink


class Match(_Frozen):
    value_id: str
    variant: Variant
    start: int
    end: int


class Decision(_Frozen):
    """Result of evaluating one (data, destination) observation against policy."""

    action: Action
    rule_id: str | None  # None means default behavior was applied
    reason: str
    severity: Severity = Severity.MEDIUM


class Finding(_Frozen):
    id: str  # "SS-LOG-001"
    rule_id: str | None
    scenario: str
    category: Category
    severity: Severity
    action: Action  # deny or warn
    expected: str
    observed: str
    component: str
    location: str | None
    destination: Destination
    data_type: DataType
    value_id: str
    variant: Variant
    evidence: str  # already redacted, e.g. "...token=[REDACTED:sv_3f9a1c]..."
    detection_method: str
    confidence: str  # "exact" | "normalized"
    remediation: str
    event_id: str
    occurrences: int = 1  # same (scenario, value, destination, component, location) deduplicated
    review_status: str | None = None


class ScenarioStatus(enum.StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    WARNED = "warned"
    ERRORED = "errored"  # scenario crashed: not a privacy finding
    SKIPPED = "skipped"


class ScenarioResult(_Frozen):
    name: str
    category: Category
    status: ScenarioStatus
    findings: list[Finding] = Field(default_factory=list)
    events_observed: int = 0
    duration_ms: float = 0.0
    error: str | None = None  # redacted
    skipped_reason: str | None = None


class Coverage(_Frozen):
    """What was actually observed. Prevents false assurance."""

    inspectors_active: list[str]
    destinations_observed: list[Destination]
    offline: bool
    limitations: list[str]


class RunSummary(_Frozen):
    total: int
    passed: int
    failed: int
    warned: int
    errored: int
    skipped: int
    findings: int


class Report(_Frozen):
    schema_version: str = "1"
    run_id: str
    tool_version: str
    started_at: dt.datetime
    finished_at: dt.datetime
    seed: int | None
    config_path: str | None
    summary: RunSummary
    results: list[ScenarioResult]
    coverage: Coverage

    @property
    def findings(self) -> list[Finding]:
        return [f for r in self.results for f in r.findings]

    @property
    def exit_code(self) -> int:
        """0 = clean, 1 = privacy findings (deny), 2 = scenario errors only."""
        if self.summary.failed:
            return 1
        if self.summary.errored:
            return 2
        return 0
