# Installation

secretsift needs Python 3.11 or newer. Its only runtime dependencies are `pydantic>=2.6` and
`pyyaml>=6.0`. `httpx` and `pytest` are optional.

## Run from a source checkout (no install step)

This is the path used to produce every command output in these docs. From the repository root:

```bash
PYTHONPATH=src python3 -m secretsift version
```

Output:

```text
secretsift 0.1.0
```

## Install with pip

`pyproject.toml` defines a standard `hatchling` build and a `secretsift` console script
(`secretsift.cli:app`). From a checkout:

```bash
python -m pip install .
```

Optional extras defined in `pyproject.toml`:

| Extra | Adds | Needed for |
| --- | --- | --- |
| `httpx` | `httpx>=0.27` | `secretsift.integrations.httpx_transport.SecretsiftTransport` |
| `pytest` | `pytest>=8` | the `secretsift` pytest fixture (registered through the `pytest11` entry point) |
| `dev` | pytest, pytest-cov, httpx, ruff, mypy, types-PyYAML | contributing |

Example: `python -m pip install ".[pytest,httpx]"`.

Note: the pip commands above were not executed while writing these docs because the build
environment had no access to PyPI. The checkout path above was executed. This documentation does
not claim that a package named `secretsift` is published on any index; see [limitations](limitations.md).

## Check the environment

```bash
secretsift doctor
```

Real output from an environment without httpx and pytest:

```text
[  ok] python 3.13.16 (needs >= 3.11)
[  ok] config secretsift.yaml is valid
[  ok] report directory secretsift-reports is writable
[warn] httpx missing (optional: httpx transport)
[warn] pytest missing (optional: pytest plugin)
[info] provider anthropic: ANTHROPIC_API_KEY is not set
[info] provider gemini: GEMINI_API_KEY is not set
[  ok] provider llama_cpp: no credentials required; endpoint http://127.0.0.1:8080/v1
[  ok] provider mock: offline mock provider (behavior=safe)
[  ok] provider ollama: no credentials required; endpoint http://127.0.0.1:11434
[info] provider openai: OPENAI_API_KEY is not set
[info] provider openai_compatible: requires base_url in config
[  ok] offline mode is on
```

`doctor` exits 3 when the Python version is too old, the config is invalid, or the report
directory is not writable; otherwise 0. If no config file exists it prints
`[warn] config secretsift.yaml not found (run: secretsift init)`.

## Uninstall / cleanup

secretsift writes only the files you ask for: the config from `secretsift init` and the report
directory (default `secretsift-reports/`). Delete those to clean up.

Next: [quickstart](quickstart.md).
