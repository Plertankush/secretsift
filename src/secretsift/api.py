"""Python SDK: use secretsift inside any test code without a YAML config.

Example::

    with Drill(offline=True) as d:
        key = d.secret("customer_api_key", "synthetic_api_key")
        my_app(key)
    d.assert_clean()
"""

from __future__ import annotations

import datetime as dt
import re
import time
import uuid
from pathlib import Path
from types import TracebackType

from secretsift.core.analysis import analyze
from secretsift.core.context import RunContext
from secretsift.core.lifecycle import Lifecycle
from secretsift.core.runner import LIMITATIONS
from secretsift.core.scenario import LABEL_PATTERN
from secretsift.exceptions import ConfigError
from secretsift.inspectors import default_inspectors
from secretsift.instrumentation import Instrumentation
from secretsift.models import (
    WILDCARD,
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
)
from secretsift.policies.evaluator import CompiledRule, PolicyEvaluator
from secretsift.reporting import TerminalReporter, write_report
from secretsift.version import __version__

_LABEL = re.compile(r"^" + LABEL_PATTERN + r"$")
_DEFAULT_SCENARIO = "drill"


def blocking_message(findings: list[Finding], *, allow_warn: bool = False) -> str | None:
    """Redacted multi-line failure text for ``findings``, or ``None`` when none block."""
    from secretsift.assertions import assert_no_findings

    try:
        assert_no_findings(findings, allow_warn=allow_warn)
    except AssertionError as exc:
        return str(exc)
    return None


class Drill:
    """Context manager that watches code for leaks of synthetic secrets.

    Default policy: every observation of a planted secret is denied except the approved test
    input. Use :meth:`allow`, :meth:`warn` and :meth:`deny` to adjust. Raw values are only
    returned by :meth:`secret`; findings, reports and ``repr`` never contain them.
    """

    def __init__(
        self,
        *,
        policy: str = "strict",
        offline: bool = True,
        seed: int | None = None,
        scenario: str = _DEFAULT_SCENARIO,
    ) -> None:
        if policy not in ("strict", "warn_only"):
            raise ConfigError("policy must be 'strict' or 'warn_only'")
        self._mode = policy
        self._offline = offline
        self._seed = seed
        self._scenario = scenario
        self._rules: dict[tuple[str, str], CompiledRule] = {}
        self._types: dict[str, DataType] = {}
        self._ctx: RunContext | None = None
        self._lifecycle: Lifecycle | None = None
        self._inst: Instrumentation | None = None
        self._started = 0.0
        self._started_at = dt.datetime.now(dt.UTC)
        self._final: Report | None = None
        self._entered = False

    def __repr__(self) -> str:
        return f"Drill(scenario={self._scenario!r}, offline={self._offline})"

    @property
    def active(self) -> bool:
        """True between ``__enter__`` and ``__exit__``."""
        return self._ctx is not None

    def __enter__(self) -> Drill:
        if self._entered:
            raise ConfigError("a Drill can be used only once; create a new one")
        self._entered = True
        ctx = RunContext(scenario=self._scenario, run_id=uuid.uuid4().hex[:12], seed=self._seed)
        lifecycle = Lifecycle(ctx)
        inst = Instrumentation(ctx.collector, offline=self._offline)
        inst.__enter__()
        self._ctx, self._lifecycle, self._inst = ctx, lifecycle, inst
        self._started = time.perf_counter()
        self._started_at = dt.datetime.now(dt.UTC)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        inst, lifecycle = self._inst, self._lifecycle
        try:
            if inst is not None:
                inst.__exit__(exc_type, exc, tb)  # drains captured stdio before analysis
            self._final = self._build_report()
        finally:
            self._inst = None
            if lifecycle is not None:
                lifecycle.__exit__(None, None, None)
            self._ctx = None

    def secret(self, label: str, data_type: str | DataType = DataType.CUSTOM) -> str:
        """Generate and register a synthetic value; returns the raw value for use as input."""
        from secretsift.synthetic.generator import generate_value

        ctx = self._require_active()
        if not _LABEL.match(label):
            raise ConfigError("label must start with a letter or '_' and use letters, digits, _.-")
        if label in self._types:
            raise ConfigError(f"secret label {label!r} is already registered")
        try:
            dtype = DataType(data_type)
        except ValueError:
            known = ", ".join(t.value for t in DataType)
            raise ConfigError(f"unknown data type; expected one of: {known}") from None
        value = generate_value(label, dtype, run_id=ctx.run_id, seed=self._seed)
        ctx.add_value(value)
        self._types[label] = dtype
        return value.value

    def allow(self, label: str, destination: str | Destination = WILDCARD) -> None:
        """Permit ``label`` (a secret label, data type or ``*``) at ``destination``."""
        self._add_rule(label, destination, Action.ALLOW, None)

    def warn(self, label: str, destination: str | Destination = WILDCARD) -> None:
        """Report ``label`` at ``destination`` as a warning instead of a failure."""
        self._add_rule(label, destination, Action.WARN, None)

    def deny(
        self,
        label: str,
        destination: str | Destination = WILDCARD,
        severity: Severity = Severity.HIGH,
    ) -> None:
        """Explicitly deny ``label`` at ``destination`` (overrides a broader allow)."""
        self._add_rule(label, destination, Action.DENY, severity)

    @property
    def findings(self) -> list[Finding]:
        """Findings so far (live while active, frozen after exit)."""
        return list(self.to_report().findings)

    def to_report(self) -> Report:
        """Assemble a :class:`Report` from everything observed so far."""
        if self._final is not None:
            return self._final
        self._require_active()
        return self._build_report()

    def report(self, fmt: str = "terminal", path: str | Path | None = None) -> str:
        """Render the report as ``fmt``; also write it safely to ``path`` when given."""
        rep = self.to_report()
        if path is not None:
            return write_report(rep, fmt, path).read_text(encoding="utf-8")
        if fmt == "terminal":
            return TerminalReporter(color=False).render(rep)
        from secretsift.reporting import get_reporter

        return get_reporter(fmt).render(rep)

    def assert_clean(self, *, allow_warn: bool = False) -> None:
        """Raise ``AssertionError`` (redacted message) if any blocking finding exists."""
        from secretsift.assertions import assert_no_findings

        assert_no_findings(self.findings, allow_warn=allow_warn)

    def _require_active(self) -> RunContext:
        if self._ctx is None:
            raise ConfigError("Drill is not active; use it as a context manager")
        return self._ctx

    def _add_rule(
        self, label: str, destination: str | Destination, action: Action, sev: Severity | None
    ) -> None:
        dest = destination.value if isinstance(destination, Destination) else destination
        if dest != WILDCARD and dest not in {d.value for d in Destination}:
            known = ", ".join(d.value for d in Destination)
            raise ConfigError(f"unknown destination; expected '*' or one of: {known}")
        if label == WILDCARD:
            kind = "any"
        elif label in {t.value for t in DataType}:
            kind = "type"
        elif _LABEL.match(label):
            kind = "label"
        else:
            raise ConfigError("label must be a secret label, a data type or '*'")
        rule = CompiledRule(
            id=f"drill-{len(self._rules) + 1}",
            scenario=None,
            data_kind=kind,
            data=label,
            destination=dest,
            action=action,
            severity=sev,
            remediation=None,
            reason=f"Drill.{action.value}({label}, {dest})",
        )
        self._rules[(label, dest)] = rule

    def _evaluator(self) -> PolicyEvaluator:
        return PolicyEvaluator(list(self._rules.values()), mode=self._mode)

    def _build_report(self) -> Report:
        ctx = self._require_active()
        events = list(ctx.collector)
        findings = analyze(
            self._scenario,
            events,
            ctx.registry,
            default_inspectors(),
            self._evaluator(),
            ctx.collector.dropped,
        )
        if any(f.action is Action.DENY for f in findings):
            status = ScenarioStatus.FAILED
        elif findings:
            status = ScenarioStatus.WARNED
        else:
            status = ScenarioStatus.PASSED
        category = findings[0].category if findings else Category.LOGGING
        result = ScenarioResult(
            name=self._scenario,
            category=category,
            status=status,
            findings=findings,
            events_observed=len(events),
            duration_ms=round((time.perf_counter() - self._started) * 1000, 3),
        )
        summary = RunSummary(
            total=1,
            passed=int(status is ScenarioStatus.PASSED),
            failed=int(status is ScenarioStatus.FAILED),
            warned=int(status is ScenarioStatus.WARNED),
            errored=0,
            skipped=0,
            findings=len(findings),
        )
        coverage = Coverage(
            inspectors_active=[i.name for i in default_inspectors()],
            destinations_observed=[
                d for d in Destination if any(e.destination is d for e in events)
            ],
            offline=self._offline,
            limitations=list(LIMITATIONS),
        )
        return Report(
            run_id=ctx.run_id,
            tool_version=__version__,
            started_at=self._started_at,
            finished_at=dt.datetime.now(dt.UTC),
            seed=self._seed,
            config_path=None,
            summary=summary,
            results=[result],
            coverage=coverage,
        )
