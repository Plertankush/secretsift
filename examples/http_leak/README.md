# http_leak: a secret in a URL query, plus the offline guard

`http_leak_app.py` starts its own HTTP server on `127.0.0.1` (random port) and calls it, so no
internet is needed. Three scenarios, synthetic data only:

* `lookup-leaky` puts the API key in the URL query string (intentionally leaky).
* `lookup-fixed` sends the key in an `X-API-Key` header and keeps the URL clean. secretsift masks
  credential headers before inspecting them, so header use is not examined (see
  `docs/limitations.md`).
* `external-call-blocked` tries `http://example.com/`. With `offline: true` the guard raises
  `OfflineViolationError` before any DNS lookup or connection; the app catches it. Loopback
  (`127.0.0.1`, `localhost`) is always allowed.

From the repository root:

```bash
PYTHONPATH=src python3 -m secretsift test --config examples/http_leak/secretsift.yaml --no-color
echo "exit code: $?"
# installed form:
secretsift test --config examples/http_leak/secretsift.yaml --no-color
```

Expected: `lookup-leaky` FAILS (`SS-NET-001`, CRITICAL, `http_request`, evidence
`http://127.0.0.1:<port>/lookup?api_key=[REDACTED:sv_...]`); the other two PASS; exit code 1.
Each scenario takes about half a second because shutting the local server down polls every 0.5 s.
