# ci_pipeline: run secretsift in GitHub Actions

Files:

* `secretsift.yaml` - a config that is expected to pass (exit code 0). Replace its `target` with a
  callable from your own project.
* `github-actions.yml` - a workflow to copy to `.github/workflows/secretsift.yml` in your repository.
  The `git+https://github.com/<owner>/secretsift.git` URL is a placeholder: install secretsift from
  wherever you obtain it.

## Run it locally

From the repository root:

```bash
PYTHONPATH=src python3 -m secretsift test --config examples/ci_pipeline/secretsift.yaml \
  --report terminal,json,html,junit --output-dir secretsift-reports/ci --no-color
echo "exit code: $?"
# installed form:
secretsift test --config examples/ci_pipeline/secretsift.yaml --report terminal,json,html,junit \
  --output-dir secretsift-reports/ci --no-color
```

Expected: `Result: PASSED`, exit code 0, and `secretsift-report.json`, `.html` and `.xml` (JUnit)
files in `secretsift-reports/ci/`.

## Exit codes

| Code | Meaning | Typical cause |
| --- | --- | --- |
| 0 | Clean | No blocking findings, no scenario errors |
| 1 | Findings | At least one `deny` finding (or any `warn` finding when `fail_on: warn`) |
| 2 | Scenario errors only | A target could not be imported or crashed, and there were no findings |
| 3 | Usage or config error | Bad YAML, wrong `version`, unknown flag, unreadable report |
| 70 | Internal error | Unexpected exception inside secretsift (set `SECRETSIFT_DEBUG=1` for a traceback) |

`fail_on` (config `report.fail_on` or `--fail-on`) controls which findings give exit code 1:
`deny` (default), `warn` (warnings fail too) or `never` (findings never fail the run; errors still
give 2). A CI job fails on any non-zero exit code, so a leak, a broken target and a bad config all
stop the pipeline.

## Catching regressions only

Keep a known-good JSON report as a baseline and pass `--baseline`:

```bash
secretsift test --config secretsift.yaml --baseline baseline/secretsift-report.json
```

This prints `regressions vs baseline: N` and the new findings; the exit code still follows
`fail_on`. To compare two reports on their own: `secretsift diff old.json new.json` (exit code 1 when
the new report has findings the old one did not).
