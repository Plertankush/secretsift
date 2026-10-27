# secretsift examples

All data is synthetic. Leaky example code is intentionally leaky and says so in its docstrings.
Run commands from the repository root; use `PYTHONPATH=src python3 -m secretsift ...` or, once
installed, `secretsift ...`.

| Example | Runs in CI | Expected outcome |
| --- | --- | --- |
| [basic_python](basic_python/) | yes | unittest using the `Drill` SDK: leaky function fails the drill, fixed passes |
| [log_leak](log_leak/) | yes | `login-leaky` FAIL (application_logs), `login-fixed` PASS |
| [http_leak](http_leak/) | yes | `lookup-leaky` FAIL (http_request), `lookup-fixed` PASS, `external-call-blocked` PASS |
| [ai_chat_app](ai_chat_app/) | yes | prompt/echo/error/stream `-leaky` FAIL, each `-fixed` PASS (mock provider) |
| [ci_pipeline](ci_pipeline/) | yes | clean scenario PASS, exit 0; GitHub Actions snippet and exit code table |
| [local_model](local_model/) | no (needs Ollama/llama.cpp) | config-only; `secretsift validate` passes |
| [hosted_api](hosted_api/) | no (needs accounts) | config-only; `validate` passes. Hosted mode (`offline: false`) sends synthetic test data to the provider and may cost money |

Exit codes: 0 pass, 1 findings, 2 runtime error, 3 config error.

`tests/integration/test_examples.py` runs every offline example and asserts the outcomes above.
