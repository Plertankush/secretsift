"""Report fixtures shared by the reporting tests."""

from __future__ import annotations

import datetime as dt
from typing import Any

from secretsift.models import (
    Action,
    Category,
    Coverage,
    DataType,
    Destination,
    Finding,
    Report,
    RunSummary,
    ScenarioResult,
    ScenarioStatus,
    Severity,
    Variant,
)

START = dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.UTC)
HOSTILE = '<script>alert(1)</script>"onmouseover="x()</style><img src=x onerror=y> ‮ \x07 é中'


def make_finding(**over: Any) -> Finding:
    data: dict[str, Any] = {
        "id": "SS-LOG-001",
        "rule_id": "R1",
        "scenario": "prevent-secret-logging",
        "category": Category.LOGGING,
        "severity": Severity.HIGH,
        "action": Action.DENY,
        "expected": "api key must not reach logs",
        "observed": "api key found in application log",
        "component": "app.auth",
        "location": "auth.py:42",
        "destination": Destination.APPLICATION_LOGS,
        "data_type": DataType.API_KEY,
        "value_id": "sv_0a1b2c3d",
        "variant": Variant.RAW,
        "evidence": "...login key=[REDACTED:sv_0a1b2c3d] ok...",
        "detection_method": "registry",
        "confidence": "exact",
        "remediation": "Do not log credentials.",
        "event_id": "ev_1",
    }
    data.update(over)
    return Finding(**data)


def make_result(
    name: str = "prevent-secret-logging",
    status: ScenarioStatus = ScenarioStatus.FAILED,
    findings: list[Finding] | None = None,
    **over: Any,
) -> ScenarioResult:
    data: dict[str, Any] = {
        "name": name,
        "category": Category.LOGGING,
        "status": status,
        "findings": [make_finding()] if findings is None else findings,
        "events_observed": 7,
        "duration_ms": 12.5,
    }
    data.update(over)
    return ScenarioResult(**data)


def make_report(results: list[ScenarioResult] | None = None, **over: Any) -> Report:
    res = [make_result()] if results is None else results
    count = lambda s: sum(1 for r in res if r.status is s)  # noqa: E731
    summary = RunSummary(
        total=len(res),
        passed=count(ScenarioStatus.PASSED),
        failed=count(ScenarioStatus.FAILED),
        warned=count(ScenarioStatus.WARNED),
        errored=count(ScenarioStatus.ERRORED),
        skipped=count(ScenarioStatus.SKIPPED),
        findings=sum(len(r.findings) for r in res),
    )
    data: dict[str, Any] = {
        "run_id": "run_abc123",
        "tool_version": "0.1.0",
        "started_at": START,
        "finished_at": START + dt.timedelta(seconds=2),
        "seed": 1337,
        "config_path": "secretsift.yaml",
        "summary": summary,
        "results": res,
        "coverage": Coverage(
            inspectors_active=["logs", "http"],
            destinations_observed=[Destination.APPLICATION_LOGS],
            offline=True,
            limitations=["Uninstrumented services are not observed."],
        ),
    }
    data.update(over)
    return Report(**data)


def mixed_report() -> Report:
    """One result per status, with deny and warn findings."""
    warn = make_finding(
        id="SS-NET-001",
        action=Action.WARN,
        severity=Severity.LOW,
        category=Category.NETWORK,
        destination=Destination.HTTP_REQUEST,
        component="httpx",
    )
    return make_report(
        [
            make_result("a-fail", ScenarioStatus.FAILED),
            make_result("b-warn", ScenarioStatus.WARNED, [warn], category=Category.NETWORK),
            make_result("c-pass", ScenarioStatus.PASSED, []),
            make_result("d-err", ScenarioStatus.ERRORED, [], error="boom"),
            make_result("e-skip", ScenarioStatus.SKIPPED, [], skipped_reason="not selected"),
        ]
    )


def hostile_report() -> Report:
    """A report whose every free-text field carries hostile content."""
    h = HOSTILE
    finding = make_finding(
        scenario=h,
        expected=h,
        observed=h,
        component=h,
        location=h,
        evidence=h * 3,
        remediation=h,
        detection_method=h,
        rule_id=h,
        confidence=h,
        id="SS-LOG-" + h,
    )
    result = make_result(h, ScenarioStatus.FAILED, [finding], error=h)
    errored = make_result(h + "2", ScenarioStatus.ERRORED, [], error=h)
    skipped = make_result(h + "3", ScenarioStatus.SKIPPED, [], skipped_reason=h)
    base = make_report([result, errored, skipped])
    cov = Coverage(
        inspectors_active=[h],
        destinations_observed=[Destination.STORAGE],
        offline=False,
        limitations=[h, "x" * 5000],
    )
    return base.model_copy(
        update={"run_id": h, "tool_version": h, "config_path": h, "coverage": cov}
    )
