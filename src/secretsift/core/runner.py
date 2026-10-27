"""Scenario runner: plants synthetic values, runs targets under instrumentation, reports."""

from __future__ import annotations

import datetime as dt
import importlib
import inspect
import sys
import time
import traceback
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from secretsift.config import SecretsiftConfig, validate_config
from secretsift.core.analysis import analyze
from secretsift.core.context import RunContext
from secretsift.core.lifecycle import Lifecycle
from secretsift.core.scenario import ScenarioSpec, render_inputs
from secretsift.evidence.redaction import redact_credentials
from secretsift.exceptions import ScenarioError
from secretsift.inspectors import default_inspectors
from secretsift.instrumentation import Instrumentation
from secretsift.models import (
    Action,
    Coverage,
    Destination,
    Finding,
    Report,
    RunSummary,
    ScenarioResult,
    ScenarioStatus,
)
from secretsift.policies.evaluator import PolicyEvaluator
from secretsift.providers import InstrumentedProvider, create_provider
from secretsift.synthetic.generator import generate_value
from secretsift.version import __version__

LIMITATIONS: list[str] = [
    "Only instrumented channels are observed: logging, stdout/stderr, http.client traffic, "
    "sockets, wrapped AI providers and explicitly configured storage paths.",
    "Uninstrumented services, subprocesses and other processes are not observed.",
    "Kernel-level and non-Python network traffic is not seen.",
    "When offline is false, hosted AI providers receive the synthetic test data.",
    "Detection is exact plus the listed encoding variants only; other transformations "
    "of a value are not detected.",
]

_MAX_ERROR_CHARS = 500


def _resolve_target(target: str, sys_path: list[str]) -> Callable[..., Any]:
    """Import ``module:callable`` with ``sys_path`` prepended; ``sys.path`` is restored."""
    module_name, _, attr = target.partition(":")
    saved = list(sys.path)
    try:
        sys.path[:0] = [str(Path(p).resolve()) for p in sys_path]
        importlib.invalidate_caches()
        try:
            obj: Any = importlib.import_module(module_name)
            for part in attr.split("."):
                obj = getattr(obj, part)
        except Exception as exc:
            raise ScenarioError(f"cannot import target {target!r}: {type(exc).__name__}") from None
    finally:
        sys.path[:] = saved
    if not callable(obj):
        raise ScenarioError(f"target {target!r} is not callable")
    return obj  # type: ignore[no-any-return]


def _accepts_provider(fn: Callable[..., Any]) -> bool:
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False
    return "provider" in params or any(
        p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()
    )


def _status(findings: list[Finding], errored: bool) -> ScenarioStatus:
    if any(f.action is Action.DENY for f in findings):
        return ScenarioStatus.FAILED
    if any(f.action is Action.WARN for f in findings):
        return ScenarioStatus.WARNED
    return ScenarioStatus.ERRORED if errored else ScenarioStatus.PASSED


def _run_scenario(
    spec: ScenarioSpec,
    cfg: SecretsiftConfig,
    evaluator: PolicyEvaluator,
    offline: bool,
    observed: set[Destination],
) -> ScenarioResult:
    started = time.perf_counter()
    ctx = RunContext(scenario=spec.name, run_id=uuid.uuid4().hex[:12], seed=cfg.seed)
    types = cfg.labels_to_types
    inspectors = default_inspectors()
    findings: list[Finding] = []
    error: str | None = None
    errored = False
    events_observed = 0
    with Lifecycle(ctx):
        try:
            labels = spec.data if spec.data is not None else list(types)
            for label in labels:
                ctx.add_value(generate_value(label, types[label], run_id=ctx.run_id, seed=cfg.seed))
            inputs = render_inputs(spec.inputs, ctx.values)
            for key, val in inputs.items():
                ctx.collector.record(
                    Destination.APPROVED_TEST_INPUT,
                    f"input.{key}",
                    str(val),
                    metadata={"input": key},
                    approved=True,
                )
            fn = _resolve_target(spec.target, cfg.sys_path)
            storage = [Path(p) for p in spec.storage_paths]
            with Instrumentation(
                ctx.collector,
                offline=offline,
                network_allowlist=cfg.network_allowlist,
                storage_paths=storage,
            ) as inst:
                kwargs = dict(inputs)
                if spec.provider is not None:
                    provider = InstrumentedProvider(
                        create_provider(spec.provider, cfg.providers), ctx.collector, inst
                    )
                    if _accepts_provider(fn):
                        kwargs["provider"] = provider
                try:
                    fn(**kwargs)
                except Exception as exc:
                    tb = "".join(traceback.format_exception(exc))
                    ctx.collector.record(
                        Destination.ERROR_REPORT,
                        "app.exception",
                        f"{type(exc).__name__}: {exc}\n{tb}",
                        metadata={"exception_type": type(exc).__name__},
                    )
                    errored = not spec.expect_exception
                    if errored:
                        msg = ctx.registry.redact(f"{type(exc).__name__}: {exc}")
                        error = redact_credentials(msg)[:_MAX_ERROR_CHARS]
                inst.snapshot_storage()
            events = list(ctx.collector)
            events_observed = len(events)
            observed.update(e.destination for e in events)
            findings = analyze(
                spec.name, events, ctx.registry, inspectors, evaluator, ctx.collector.dropped
            )
        except Exception as exc:
            errored = True
            error = redact_credentials(ctx.registry.redact(f"{type(exc).__name__}: {exc}"))[
                :_MAX_ERROR_CHARS
            ]
    return ScenarioResult(
        name=spec.name,
        category=spec.category,
        status=_status(findings, errored),
        findings=findings,
        events_observed=events_observed,
        duration_ms=round((time.perf_counter() - started) * 1000, 3),
        error=error,
    )


def run_config(
    cfg: SecretsiftConfig,
    *,
    config_path: Path | None = None,
    offline_override: bool | None = None,
    category_filter: str | None = None,
) -> Report:
    """Run every scenario in ``cfg`` and return the assembled :class:`Report`."""
    validate_config(cfg)
    evaluator = cfg.policy_evaluator()
    offline = cfg.offline if offline_override is None else offline_override
    started_at = dt.datetime.now(dt.UTC)
    observed: set[Destination] = set()
    results: list[ScenarioResult] = []
    for spec in cfg.scenarios:
        if category_filter is not None and spec.category.value != category_filter:
            results.append(
                ScenarioResult(
                    name=spec.name,
                    category=spec.category,
                    status=ScenarioStatus.SKIPPED,
                    skipped_reason=f"category {spec.category.value!r} does not match "
                    f"filter {category_filter!r}",
                )
            )
            continue
        results.append(_run_scenario(spec, cfg, evaluator, offline, observed))
    counts = {s: sum(1 for r in results if r.status is s) for s in ScenarioStatus}
    summary = RunSummary(
        total=len(results),
        passed=counts[ScenarioStatus.PASSED],
        failed=counts[ScenarioStatus.FAILED],
        warned=counts[ScenarioStatus.WARNED],
        errored=counts[ScenarioStatus.ERRORED],
        skipped=counts[ScenarioStatus.SKIPPED],
        findings=sum(len(r.findings) for r in results),
    )
    coverage = Coverage(
        inspectors_active=[i.name for i in default_inspectors()],
        destinations_observed=[d for d in Destination if d in observed],
        offline=offline,
        limitations=list(LIMITATIONS),
    )
    return Report(
        run_id=uuid.uuid4().hex[:12],
        tool_version=__version__,
        started_at=started_at,
        finished_at=dt.datetime.now(dt.UTC),
        seed=cfg.seed,
        config_path=str(config_path) if config_path is not None else None,
        summary=summary,
        results=results,
        coverage=coverage,
    )
