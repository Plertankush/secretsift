# local_model: Ollama and llama.cpp (config only)

NOT RUN IN CI. This needs a model server running on your machine, so it is excluded from
`tests/integration/test_examples.py` (that test only checks that the config validates).

The wire formats of the `ollama` and `llama_cpp` adapters were written from public API
documentation and have only been tested against fake transports, never against a live server.

1. Start a server: Ollama on `127.0.0.1:11434` (with a model pulled) and/or a llama.cpp server on
   `127.0.0.1:8080`. Set `model:` in `secretsift.yaml` to your model name.
2. Check the config (no network is used):

```bash
PYTHONPATH=src python3 -m secretsift validate --config examples/local_model/secretsift.yaml
PYTHONPATH=src python3 -m secretsift providers --config examples/local_model/secretsift.yaml
```

3. Run it:

```bash
PYTHONPATH=src python3 -m secretsift test --config examples/local_model/secretsift.yaml --no-color
# installed form:
secretsift test --config examples/local_model/secretsift.yaml --no-color
```

Expected with a working server: `ollama-leaky-chat` FAILS (the demo target prints the key and sends
it in the prompt, so it produces stdout and `ai_request` findings), the two `*-safe-chat` scenarios
PASS, exit code 1. `offline: true` stays on because loopback addresses are always reachable; the
planted values never leave your machine. If the server is down you will see errored scenarios
(exit code 2 if there are no findings).
