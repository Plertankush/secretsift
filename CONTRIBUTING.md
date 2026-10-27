# Contributing to secretsift

Thanks for helping. secretsift is a local-first tool that plants **synthetic** secrets in your own
code, observes where they surface, and reports violations of a policy you define.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
```

## Dev commands

```bash
python -m unittest discover -s tests -t . -q    # primary test command
python -m pytest -q                              # pytest runs the same unittest cases
python -m ruff check .                           # lint
python -m ruff format --check .                  # formatting (use `ruff format .` to fix)
python -m mypy                                   # strict type check of src/secretsift
```

CI runs all of these (tests on Python 3.11, 3.12, 3.13 across Linux, macOS and Windows). Please run
them locally before opening a pull request.

## Dependency policy

Runtime dependencies are **Python >= 3.11 standard library plus `pydantic` and `pyyaml` only**.
Do not add others. `httpx` and `pytest` are optional extras and may be imported only lazily inside
the modules that are explicitly optional (`integrations/httpx_transport.py` and
`integrations/pytest_plugin.py`). Never import `typer`, `rich` or `requests`. Dev-only tools
(ruff, mypy, pytest-cov) belong in the `dev` extra.

## Module boundaries

Source lives in `src/secretsift/`. `docs/DESIGN.md` is the binding reference for each module's public
API. Shared types live in `models.py`, `contracts.py`, `exceptions.py` and `core/events.py`; changes
to them need discussion first.

| Area | Modules |
| --- | --- |
| Synthetic values and evidence | `synthetic/`, `evidence/` |
| Policy and scenario engine | `config.py`, `policies/`, `core/`, `assertions/` |
| Instrumentation and inspectors | `instrumentation/`, `inspectors/`, `integrations/httpx_transport.py` |
| Providers | `providers/` |
| Reporting | `reporting/` |
| CLI, SDK, pytest plugin | `cli`, `integrations/pytest_plugin.py` |

Keep changes inside the area they belong to and depend only on the public API of other areas.

## Testing rules

- Tests are `unittest.TestCase` classes (pytest also runs them). Each test directory needs an
  `__init__.py`. Layout: `tests/unit/<area>/`, plus `tests/integration/`, `tests/security/` and
  `tests/regression/`.
- **Tests must never use the network or real credentials.** Provider adapters are tested with
  injected fake transports. Never read API keys from the environment in a test.
- Use synthetic values only (for example `sk-test-...` and `@example.test` addresses) and mark
  fixtures as synthetic.
- No `time.sleep` longer than 0.05 seconds. Tests must be deterministic.
- Add positive, negative and edge cases for each change, and a security case when output, logging or
  reporting is touched.

## Code standards

- Fully type-annotated; `mypy --strict` clean. Ruff with line length 100. Short docstrings.
- No TODOs, placeholders, stubs or dead code.
- Raw synthetic values and raw event payloads must never appear in exceptions, logs, reports, `repr`
  or `model_dump`. Real credentials must never appear anywhere.
- Same seed and config must give the same values and decisions.
- Detection is not a violation: the policy engine decides allow, warn or deny.

## Pull requests

Keep PRs focused, fill in the template, and update `CHANGELOG.md` under `Unreleased` for user-visible
changes. By contributing you agree your work is licensed under Apache-2.0. Participation is governed
by the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md), never in public issues.
