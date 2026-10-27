"""Command-line interface (argparse only). Exit codes: 0 clean, 1 findings, 2 scenario errors
only, 3 usage or configuration error, 70 unexpected internal error."""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import NoReturn

from secretsift.assertions import compare_to_baseline, regression_findings
from secretsift.config import SecretsiftConfig, dump_default_config, load_config, validate_config
from secretsift.core.runner import run_config
from secretsift.exceptions import ConfigError, SecretsiftError
from secretsift.models import Category, Finding, Report
from secretsift.providers import create_provider
from secretsift.providers.registry import provider_statuses
from secretsift.reporting import (
    TerminalReporter,
    diff_reports,
    get_reporter,
    render_diff,
    write_report,
)
from secretsift.reporting.json_report import MAX_REPORT_CHARS, loads
from secretsift.reporting.safe_io import printable, write_text_atomic
from secretsift.version import __version__

EXIT_USAGE = 3
EXIT_INTERNAL = 70
DEFAULT_CONFIG = "secretsift.yaml"
_EXT = {"json": "json", "html": "html", "junit": "xml", "terminal": "txt"}
_FILTERABLE = [c.value for c in Category if c is not Category.REGRESSION]


class _UsageError(Exception):
    """Raised by the parser instead of exiting, so ``main`` can return exit code 3."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise _UsageError(message)


def _out(text: str = "") -> None:
    print(text, file=sys.stdout)


def _err(text: str) -> None:
    print(text, file=sys.stderr)


def _build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="secretsift", description="Privacy leak rehearsal for AI apps.")
    parser.add_argument("--version", action="version", version=f"secretsift {__version__}")
    sub = parser.add_subparsers(dest="command", parser_class=_Parser)

    p = sub.add_parser("init", help="write a starter config")
    p.add_argument("path", nargs="?", default=DEFAULT_CONFIG)
    p.add_argument("--force", action="store_true", help="overwrite an existing file")

    for name, text in (
        ("doctor", "check the environment"),
        ("providers", "list AI providers and their status"),
        ("validate", "validate a config file"),
    ):
        p = sub.add_parser(name, help=text)
        p.add_argument("--config", "-c", default=DEFAULT_CONFIG)

    p = sub.add_parser("test", help="run all scenarios")
    p.add_argument("--config", "-c", default=DEFAULT_CONFIG)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--offline", dest="offline", action="store_true", default=None)
    mode.add_argument("--online", dest="offline", action="store_false")
    p.add_argument("--filter", dest="category", help="only run this category")
    p.add_argument("--report", help="comma list of terminal,json,html,junit")
    p.add_argument("--output-dir", help="report directory (default: from config)")
    p.add_argument("--fail-on", choices=["deny", "warn", "never"])
    p.add_argument("--baseline", help="previous JSON report; print regressions against it")
    p.add_argument("--seed", type=int)
    p.add_argument("--no-color", action="store_true")

    p = sub.add_parser("report", help="convert a JSON report")
    p.add_argument("file")
    p.add_argument("--format", default="terminal", choices=["terminal", "html", "junit", "json"])
    p.add_argument("--output", "-o")
    p.add_argument("--no-color", action="store_true")

    p = sub.add_parser("diff", help="compare two JSON reports")
    p.add_argument("old")
    p.add_argument("new")
    p.add_argument("--no-color", action="store_true")

    sub.add_parser("demo", help="run the starter config and write reports")
    sub.add_parser("version", help="print the version")
    return parser


def _load_report(path: str) -> Report:
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read(MAX_REPORT_CHARS + 1)
    except (OSError, UnicodeDecodeError) as exc:
        reason = getattr(exc, "strerror", None) or "not valid UTF-8"
        raise ConfigError(f"cannot read report {Path(path).name!r}: {reason}") from None
    return loads(text)


def _color(args: argparse.Namespace) -> bool | None:
    return False if getattr(args, "no_color", False) else None


def _exit_code(report: Report, fail_on: str) -> int:
    summary = report.summary
    if fail_on == "never":
        return 2 if summary.errored else 0
    if summary.failed or (fail_on == "warn" and summary.warned):
        return 1
    return 2 if summary.errored else 0


def _finding_line(finding: Finding) -> str:
    text = (
        f"  {finding.id} [{finding.severity.value}] scenario {finding.scenario!r}: "
        f"{finding.observed}"
    )
    return printable(text, limit=300)


def _write_formats(
    report: Report,
    formats: Sequence[str],
    directory: Path,
    color: bool | None,
    path_sink: Callable[[str], None],
) -> None:
    for fmt in formats:
        if fmt == "terminal":
            _out(TerminalReporter(color=color).render(report))
        else:
            target = directory / f"secretsift-report.{_EXT[fmt]}"
            path_sink(f"report written: {write_report(report, fmt, target)}")


def _parse_formats(text: str) -> list[str]:
    formats = [f.strip().lower() for f in text.split(",") if f.strip()]
    for fmt in formats:
        get_reporter(fmt)
    if not formats:
        raise ConfigError("--report needs at least one format")
    return formats


def _cmd_init(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if (path.exists() or path.is_symlink()) and not args.force:
        _err(f"error: {path} already exists; use --force to overwrite")
        return EXIT_USAGE
    write_text_atomic(path, dump_default_config(), mode=0o644)
    _out(f"wrote {path}")
    _err(f"next: secretsift test --config {path}")
    return 0


def _load(args: argparse.Namespace) -> SecretsiftConfig:
    cfg = load_config(Path(args.config))
    for warning in validate_config(cfg):
        _err(f"warning: {warning}")
    return cfg


def _cmd_validate(args: argparse.Namespace) -> int:
    cfg = _load(args)
    _out(
        f"config OK: {len(cfg.scenarios)} scenario(s), "
        f"{len(cfg.synthetic.values)} synthetic value(s), offline={str(cfg.offline).lower()}"
    )
    return 0


def _writable(directory: Path) -> bool:
    probe = directory.resolve()
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    return probe.is_dir() and os.access(probe, os.W_OK | os.X_OK)


def _cmd_doctor(args: argparse.Namespace) -> int:
    failed = False

    def line(state: str, text: str) -> None:
        _out(f"[{state:>4}] {text}")

    v = sys.version_info
    ok = v >= (3, 11)
    failed |= not ok
    line("ok" if ok else "FAIL", f"python {v.major}.{v.minor}.{v.micro} (needs >= 3.11)")
    cfg: SecretsiftConfig | None = None
    path = Path(args.config)
    if not path.exists():
        line("warn", f"config {path} not found (run: secretsift init)")
    else:
        try:
            cfg = load_config(path)
            validate_config(cfg)
            line("ok", f"config {path} is valid")
        except SecretsiftError as exc:
            cfg = None
            failed = True
            line("FAIL", f"config {path} is invalid: {printable(str(exc).splitlines()[0])}")
    report_dir = Path(cfg.report.dir if cfg else "secretsift-reports")
    if _writable(report_dir):
        line("ok", f"report directory {report_dir} is writable")
    else:
        failed = True
        line("FAIL", f"report directory {report_dir} is not writable")
    for module, why in (("httpx", "httpx transport"), ("pytest", "pytest plugin")):
        found = importlib.util.find_spec(module) is not None
        state = "present" if found else "missing"
        line("ok" if found else "warn", f"{module} {state} (optional: {why})")
    for name, status in provider_statuses():
        line("ok" if status.configured else "info", f"provider {name}: {printable(status.detail)}")
    offline = cfg.offline if cfg else True
    line("ok", f"offline mode is {'on' if offline else 'off'}{'' if cfg else ' by default'}")
    return EXIT_USAGE if failed else 0


def _cmd_providers(args: argparse.Namespace) -> int:
    rows = [(name, "built-in", s.configured, s.detail) for name, s in provider_statuses()]
    path = Path(args.config)
    if path.exists():
        cfg = load_config(path)
        for name in cfg.providers:
            status = create_provider(name, cfg.providers).status()
            rows.append((name, "config", status.configured, status.detail))
    _out(f"{'NAME':<20} {'SOURCE':<9} {'STATUS':<15} DETAIL")
    for name, source, configured, detail in rows:
        state = "configured" if configured else "not configured"
        _out(f"{printable(name):<20} {source:<9} {state:<15} {printable(detail)}")
    return 0


def _cmd_test(args: argparse.Namespace) -> int:
    cfg = _load(args)
    if args.category is not None and args.category not in _FILTERABLE:
        raise ConfigError(f"--filter must be one of: {', '.join(_FILTERABLE)}")
    formats = _parse_formats(args.report) if args.report else list(cfg.report.formats)
    baseline = _load_report(args.baseline) if args.baseline else None
    if args.seed is not None:
        cfg = cfg.model_copy(update={"seed": args.seed})
    report = run_config(
        cfg,
        config_path=Path(args.config),
        offline_override=args.offline,
        category_filter=args.category,
    )
    directory = Path(args.output_dir or cfg.report.dir)
    _write_formats(report, formats, directory, _color(args), _err)
    if baseline is not None:
        regressions = regression_findings(compare_to_baseline(baseline, report))
        _out(f"regressions vs baseline: {len(regressions)}")
        for finding in regressions:
            _out(_finding_line(finding))
    return _exit_code(report, args.fail_on or cfg.report.fail_on)


def _cmd_report(args: argparse.Namespace) -> int:
    report = _load_report(args.file)
    if args.format == "terminal":
        text = TerminalReporter(color=False if args.output else _color(args)).render(report)
    else:
        text = get_reporter(args.format).render(report)
    if args.output:
        _out(f"wrote {write_text_atomic(args.output, text)}")
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")
    return 0


def _cmd_diff(args: argparse.Namespace) -> int:
    diff = diff_reports(_load_report(args.old), _load_report(args.new))
    _out(render_diff(diff, color=_color(args)))
    return 1 if diff.has_new else 0


def _cmd_demo(_args: argparse.Namespace) -> int:
    with tempfile.TemporaryDirectory(prefix="secretsift-demo-") as tmp:
        config_path = Path(tmp) / DEFAULT_CONFIG
        write_text_atomic(config_path, dump_default_config())
        cfg = load_config(config_path)
        report = run_config(cfg, config_path=None, offline_override=True)
    _out(TerminalReporter().render(report))
    directory = Path("secretsift-reports")
    for fmt in ("json", "html"):
        _out(f"report written: {write_report(report, fmt, directory / f'secretsift-report.{fmt}')}")
    _err("the leaky-login scenario is meant to fail: it is the demo of what secretsift catches")
    return 0


def _cmd_version(_args: argparse.Namespace) -> int:
    _out(f"secretsift {__version__}")
    return 0


_COMMANDS: dict[str, Callable[[argparse.Namespace], int]] = {
    "init": _cmd_init,
    "doctor": _cmd_doctor,
    "providers": _cmd_providers,
    "validate": _cmd_validate,
    "test": _cmd_test,
    "report": _cmd_report,
    "diff": _cmd_diff,
    "demo": _cmd_demo,
    "version": _cmd_version,
}


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return the process exit code."""
    parser = _build_parser()
    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except _UsageError as exc:
        _err(f"error: {exc}")
        _err("run 'secretsift --help' for usage")
        return EXIT_USAGE
    except SystemExit as exc:  # --help / --version
        return exc.code if isinstance(exc.code, int) else 0
    if args.command is None:
        parser.print_help(sys.stderr)
        return EXIT_USAGE
    try:
        return _COMMANDS[args.command](args)
    except SecretsiftError as exc:
        _err(f"error: {printable(str(exc), keep_newlines=True)}")
        return EXIT_USAGE
    except KeyboardInterrupt:
        _err("interrupted")
        return 130
    except Exception as exc:
        if os.environ.get("SECRETSIFT_DEBUG") == "1":
            raise
        _err(f"internal error: {type(exc).__name__} (set SECRETSIFT_DEBUG=1 for a traceback)")
        return EXIT_INTERNAL


def app() -> None:
    """Console-script entry point."""
    sys.exit(main())
