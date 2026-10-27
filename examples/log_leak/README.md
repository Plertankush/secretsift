# log_leak: a secret written to the application log

`log_leak_app.py` has `leaky_login` (logs the API key; intentionally leaky) and `fixed_login`
(logs a masked hint). `secretsift.yaml` runs both. Synthetic data only.

From the repository root:

```bash
PYTHONPATH=src python3 -m secretsift test --config examples/log_leak/secretsift.yaml --no-color
echo "exit code: $?"
# installed form:
secretsift test --config examples/log_leak/secretsift.yaml --no-color
```

Expected: `login-leaky` FAILS with finding `SS-LOG-001` (HIGH, `application_logs`, evidence
`login attempt user=alice api_key=[REDACTED:sv_...]`); `login-fixed` PASSES; exit code 1. Reports go
to `secretsift-reports/log_leak/` (JSON and HTML).

`sys_path: ["examples/log_leak"]` is resolved against the directory you run the command from. If
you run it from elsewhere, change that path.
