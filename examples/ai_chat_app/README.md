# ai_chat_app: leaks through an AI provider (offline mock)

`chat_app.py` has four leaky targets and four fixed ones, run against secretsift's offline `mock`
provider (no model, no network). Synthetic data only; the leaky functions are intentionally leaky.

| Scenario pair | Mock behavior | What leaks | Fix |
| --- | --- | --- | --- |
| `prompt-*` | `safe` | email pasted into the prompt (`ai_request`) | do not send it |
| `echo-*` | `echo` | model repeats the email (`ai_output`) | do not send it |
| `error-*` | `leaky_error` | provider error quotes the prompt (`error_report`) | send a pseudonym |
| `stream-*` | `echo`, `chunk_size: 5` | email echoed, split across chunks (`ai_output`) | do not send it |

For the last three, `approved_destinations: [ai_request]` accepts the prompt itself so the finding
isolates the output or error leak. For streaming, no single 5-character chunk contains the value;
the provider wrapper also records the joined text, which is where it is caught.

From the repository root:

```bash
PYTHONPATH=src python3 -m secretsift test --config examples/ai_chat_app/secretsift.yaml --no-color
echo "exit code: $?"
# installed form:
secretsift test --config examples/ai_chat_app/secretsift.yaml --no-color
```

Expected: the four `*-leaky` scenarios FAIL (5 findings: `SS-CTX-001`, `SS-RSP-001` twice, and two
for `error-leaky`: one from the provider wrapper, one from the app's uncaught exception); the four
`*-fixed` scenarios PASS; exit code 1.

Important: `ai_output` and provider errors are recorded at the provider boundary, before your app
post-processes them. Filtering the reply afterwards does not make the `ai_output` finding go away;
the fix is to stop giving the model the secret (or to fix what the model is allowed to echo).

## What the HTML report looks like

Real report of this example (8 scenarios, 5 intentional leaks), in three readable parts.
Live version: [../../docs/sample/ai-chat-report.html](../../docs/sample/ai-chat-report.html).

![Part 1](../../docs/images/report-preview-1.png)

![Part 2](../../docs/images/report-preview-2.png)

![Part 3](../../docs/images/report-preview-3.png)

Whole page in one image: [../../docs/images/report-preview-full.png](../../docs/images/report-preview-full.png).
