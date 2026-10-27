# basic_python: the Drill SDK inside a unittest

`my_app.py` contains an intentionally leaky function (`leaky_signup`, logs a password) and its
fixed version (`fixed_signup`). `test_my_app_privacy.py` uses `secretsift.Drill` to plant synthetic
values, run the code and assert on the result. Synthetic data only.

From the repository root:

```bash
PYTHONPATH=src python3 -m unittest discover -s examples/basic_python -v
# installed form:
python3 -m unittest discover -s examples/basic_python -v
```

Expected: 3 tests pass. The fixed function is clean; the leaky one is caught (one finding at
`application_logs`, and the `AssertionError` text contains no raw secret); an `allow`/`warn` rule
turns the same flow into an accepted one or a warning. The `welcome ...` lines on the console are
the leaky function's own `print` call.

With pytest installed the plugin also offers a `secretsift` fixture (see `docs/quickstart.md`).
