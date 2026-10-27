# hosted_api: OpenAI, Anthropic and Gemini (config only)

NOT RUN IN CI. This needs live accounts, costs money and sends data off your machine, so
`tests/integration/test_examples.py` only checks that the config validates.

WARNING (cost and data sharing): with `offline: false` secretsift sends the scenarios' prompts to the
hosted provider. They contain only synthetic test data, but that data still leaves your machine and
is subject to the provider's terms, retention and billing. The `safe_chat` target used here sends a
harmless note rather than the planted key; switching a scenario to `secretsift.demo:leaky_chat` would
deliberately send the synthetic key to the provider. Use a throwaway key with a low spending limit.

The OpenAI, Anthropic and Gemini wire formats were implemented from public API documentation and
have been tested only against fake transports. They have not been verified against the live
services. Treat first runs as experiments.

1. Export credentials as environment variables (never put keys in the YAML; secretsift accepts only
   the variable's name via `api_key_env`):

```bash
export OPENAI_API_KEY=...
export ANTHROPIC_API_KEY=...
export GEMINI_API_KEY=...
```

2. Set `model:` in `secretsift.yaml` to a model your account can use. Check the config offline:

```bash
PYTHONPATH=src python3 -m secretsift validate --config examples/hosted_api/secretsift.yaml
PYTHONPATH=src python3 -m secretsift providers --config examples/hosted_api/secretsift.yaml
```

3. Run it (the config already sets `offline: false`; `--online` makes that explicit):

```bash
PYTHONPATH=src python3 -m secretsift test --config examples/hosted_api/secretsift.yaml --online --no-color
# installed form:
secretsift test --config examples/hosted_api/secretsift.yaml --online --no-color
```

`network_allowlist` limits outbound connections to the three provider hosts while scenarios run.
Expected with valid accounts: three PASSED scenarios and exit code 0. A missing key gives an errored
scenario naming the environment variable.
