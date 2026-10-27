## Summary

<!-- What does this change and why? -->

## Checklist

- [ ] `python -m unittest discover -s tests -t . -q` passes
- [ ] `python -m ruff check .` and `python -m ruff format --check .` pass
- [ ] `python -m mypy` passes
- [ ] Tests added or updated; they use no network and no real credentials
- [ ] No new runtime dependency (only pydantic and pyyaml are allowed)
- [ ] No raw synthetic values or credentials in logs, errors, reports, or `repr`
- [ ] `CHANGELOG.md` updated under `Unreleased` for user-visible changes
