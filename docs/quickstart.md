# Quickstart

All output below was produced by running the commands (offline, with `PYTHONPATH=src`; if you
installed the package, drop the prefix and use `secretsift ...`).

## 1. See it work: the built-in demo

```bash
secretsift demo
```

`demo` writes the starter config to a temporary directory, runs it offline, prints the terminal
report and writes `secretsift-reports/secretsift-report.json` and `.html` into the current
directory. One scenario (`leaky-login`) is intended to fail; it is a demo target that logs a
planted API key. It always exits 0.

## 2. Test your own code

Create a function that leaks a secret into a log (`myapp.py`):

```python
import logging

log = logging.getLogger("myapp")


def login(api_key: str, user: str) -> str:
    log.info("login user=%s key=%s", user, api_key)  # leaks the key
    return "ok"
```

Create the config (`secretsift.yaml`). `secretsift init` writes a fuller annotated starter file;
this one is minimal:

```yaml
version: 1
seed: 7
report:
  dir: secretsift-reports
  formats: [terminal, json]
synthetic:
  values:
    - {label: customer_api_key, type: synthetic_api_key}
policy:
  default_action: deny
scenarios:
  - name: login-does-not-log-key
    category: logging
    target: "myapp:login"
    inputs: {api_key: "{{ customer_api_key }}", user: alice}
    data: [customer_api_key]
```

Validate, then run:

```bash
secretsift validate
secretsift test
```

```text
config OK: 1 scenario(s), 1 synthetic value(s), offline=true
...
Result:   FAILED
          1 scenarios: 0 passed, 1 failed, 0 warned, 0 errored, 0 skipped; 1 findings
...
  SS-LOG-001  MEDIUM  DENY  logging
    scenario: login-does-not-log-key
    expected: customer_api_key (synthetic_api_key) must not reach application_logs
    observed: customer_api_key observed in application_logs via myapp
    where: application_logs / myapp @ myapp.py:7
    data: synthetic_api_key (sv_1471ae60), matched as raw, exact
    evidence: login user=alice key=[REDACTED:sv_1471ae60]
    fix: Do not log sensitive values; mask or drop the field before it reaches the logger.
```

The process exits 1. The finding names the component (`myapp`) and the location (`myapp.py:7`):
that is the line in your own code to change. Remove the key from the log call:

```python
    log.info("login user=%s", user)
```

Run again: `Result: PASSED`, exit code 0.

How it works: secretsift generated a fake API key, substituted it for `{{ customer_api_key }}` in
the `inputs`, called `myapp.login(api_key=..., user="alice")` while watching logging, stdout/stderr,
`http.client`, sockets and wrapped AI providers, and then checked what it saw against the policy.
The raw value never appears in reports; evidence shows `[REDACTED:<id>]`.

## 3. Compare runs and export

```bash
secretsift test --report json --output-dir old       # run on the leaky code
# ... fix the code ...
secretsift test --report json --output-dir new
secretsift diff old/secretsift-report.json new/secretsift-report.json
```

```text
secretsift report diff
  baseline: 4c897378cb05
  current:  5e3436f17ed2

New findings (0)
  none

Fixed findings (1)
  - SS-LOG-001 [medium] logging via application_logs in scenario 'login-does-not-log-key' (component myapp)

Unchanged findings (0)
  none

Result: 0 new, 1 fixed, 0 unchanged
```

`diff` exits 1 only when there are new findings. Other useful commands:

```bash
secretsift test --baseline old/secretsift-report.json   # prints "regressions vs baseline: N"
secretsift report old/secretsift-report.json --format junit -o out.xml
secretsift test --filter network                       # other categories are SKIPPED
secretsift test --fail-on never                        # exit 0 even with findings
```

## 4. Use it inside unit tests (no YAML)

```python
import logging

from secretsift import Drill

log = logging.getLogger("app")


def my_app(key: str) -> None:
    log.info("got key %s", key)


with Drill(offline=True, seed=1) as d:
    key = d.secret("customer_api_key", "synthetic_api_key")
    my_app(key)

d.assert_clean()  # raises AssertionError: "secretsift: 1 privacy finding(s) ..."
```

The failure message is redacted (the file name and line come from wherever the snippet was run):

```text
secretsift: 1 privacy finding(s)
  [SS-LOG-001] deny/medium application_logs in app@sdk_demo.py:9 (scenario 'drill', value sv_6bae6818, x1)
      evidence: got key [REDACTED:sv_6bae6818]
      fix: Do not log sensitive values; mask or drop the field before it reaches the logger.
```

`Drill` methods: `secret(label, data_type)`, `allow/warn/deny(label, destination="*")`,
`findings`, `to_report()`, `report(fmt, path)`, `assert_clean(allow_warn=False)`. A `Drill` can
be entered once. With pytest installed, a `secretsift` fixture is registered automatically; it
yields a fresh offline `Drill` and fails the test at teardown if there are findings (opt out per
test with `@pytest.mark.secretsift_allow_findings`):

```python
def test_no_leak(secretsift):
    key = secretsift.secret("customer_api_key", "synthetic_api_key")
    my_app(key)
```

This pytest snippet was not executed here because pytest is not installed in this environment
(see [limitations](limitations.md)); the `Drill` calls it makes are the ones run above.

Next: [configuration](configuration.md), [policy_reference](policy_reference.md),
[troubleshooting](troubleshooting.md). Runnable examples live in `../examples/`.
