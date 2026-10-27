# secretsift: design contract

Binding reference for every module. Source of truth for shared types: `src/secretsift/models.py`,
`contracts.py`, `exceptions.py`, `core/events.py`. Do not change those files; report needed changes.

## 1. What it is

Local-first developer tool. A developer points secretsift at their code (a Python callable, optionally
using an AI provider). secretsift plants **synthetic** secrets, runs the scenario while instrumentation
records where data surfaces (logs, stdout, exceptions, HTTP, AI requests/outputs, configured storage),
evaluates each observation against a **policy**, and emits redacted-evidence reports:
terminal, JSON, HTML (self-contained file), JUnit XML. No frontend, no SaaS.

Core rule: **detection is not violation.** A value being found is an observation; the policy engine
decides allow / warn / deny. Only deny (and warn, as WARNED) produce findings.

## 2. Hard constraints (all agents)

* Runtime deps: Python >= 3.11 stdlib + `pydantic>=2.6` + `pyyaml` ONLY. `httpx` and `pytest` are
  optional and may be imported only lazily inside the modules that are explicitly optional
  (`integrations/httpx_transport.py`, `integrations/pytest_plugin.py`). Never import typer/rich/requests.
* No network in tests. No test may need pip/PyPI. No `time.sleep` > 0.05s in tests.
* Tests are `unittest.TestCase` (pytest runs them too). Run with:
  `cd /home/claude/secretsift && PYTHONPATH=src python3 -m unittest discover -s tests -t . -q`
  Each test directory needs `__init__.py`. Tests live under `tests/unit/<area>/` (or `tests/integration/`,
  `tests/security/`, `tests/regression/` where stated).
* Fully type-annotated (mypy --strict clean in spirit), ruff-style, line length 100, short docstrings.
* No TODO / placeholder / empty stub / dead code / fabricated claims. Everything shipped is implemented and tested.
* Raw synthetic values and raw event payloads must never appear in exceptions, logs, reports, repr,
  or `model_dump`. Real credentials (API keys read from env) must never appear anywhere either.
* Never modify files outside your ownership list. Never run git commit.
* Deterministic: same seed + config => same values and same decisions.
* Final message to the coordinator: <= 150 words: files written, public API, deviations, open issues.

## 3. Module ownership and public API

Package root `src/secretsift/`. Exact signatures below are what other modules import; match them.

### A. synthetic + evidence  (owner: agent A)
Files: `synthetic/{__init__,generator,markers,registry,normalize,fixtures}.py`, `evidence/{__init__,redaction}.py`,
tests `tests/unit/synthetic/`, `tests/unit/evidence/`, `tests/security/test_redaction_security.py`.
* `generator.generate_value(label: str, data_type: DataType, *, run_id: str, seed: int | None) -> SyntheticValue`
  Deterministic when seed is not None (derive via HMAC-SHA256 of seed/run_id/label; never `random` global state;
  when seed is None use `secrets`). Format-preserving per type: API key `sk-test-<...>`, bearer token (JWT-looking
  `eyJ...` three segments, clearly fake), password, session id (hex), email `<local>@example.test`, phone
  `+1-555-01xx-xxxx` style fictional, name, customer id `CUST-...`, custom. Each value embeds a unique per-run
  `marker` (>= 8 chars) and has length >= 12. `id` = `sv_` + 8 hex. `marker` unique per (run_id, label).
* `registry.SecretRegistry` implements `SecretRegistryProtocol`. `find(text)` returns matches for raw value and
  these variants: casefold, url_encoded (quote and quote_plus), base64 (std + urlsafe, all 3 alignment offsets,
  padding-agnostic), hex (lower/upper), json_escaped, whitespace_stripped. Offsets refer to the ORIGINAL text.
  Overlaps merged; sorted by start. Efficient for payloads up to 1 MB (no catastrophic regex; compile once).
  `redact(text)` replaces every matched span with `[REDACTED:<value_id>]`; idempotent; after redact,
  `find(redacted)` must be empty. Thread-safe.
* `markers.py`: marker creation helpers. `normalize.py`: pure variant-building functions (unit-testable).
* `fixtures.py`: `generate_set(specs, run_id, seed)` helper returning list[SyntheticValue] from (label, type) pairs.
* `evidence.redaction.build_evidence(event: Event, matches: list[Match], registry: SecretRegistryProtocol,
  window: int = 40) -> str`: snippet of `event.payload` around the first match (+/- window chars), fully redacted
  via the registry, whitespace/control chars made printable, max 240 chars, prefixed/suffixed with `...` when cut.
  Also `redact_text(text, registry) -> str` and `redact_credentials(text: str) -> str` (masks `sk-...`, `Bearer ...`,
  `Authorization:`-style values, `api_key=` params, long base64-like tokens after known key names).

### B. policy + scenario engine  (owner: agent B)
Files: `config.py`, `policies/{__init__,schema,loader,evaluator,rules}.py`,
`core/{scenario,context,lifecycle,runner,analysis}.py`, `assertions/{__init__,privacy,regression}.py`,
tests `tests/unit/policies/`, `tests/unit/core/`, `tests/regression/`.
* `config.py`: pydantic models `SecretsiftConfig`, `SyntheticSpec`, `ReportSpec`; `load_config(path: Path) -> SecretsiftConfig`
  (yaml.safe_load only, size limit 1 MB, helpful `ConfigError`), `validate_config(cfg) -> list[str]` (warnings) and
  `dump_default_config() -> str` (annotated starter yaml used by `secretsift init`).
  YAML shape (all keys validated, `extra="forbid"`, `version: 1` required):
  ```yaml
  version: 1
  seed: 1337                      # optional int
  offline: true                   # default true; blocks non-loopback network
  network_allowlist: []           # hosts permitted when offline: false
  sys_path: ["."]                 # dirs prepended to sys.path to import targets
  report: {dir: secretsift-reports, formats: [terminal, json, html], fail_on: deny}  # fail_on: deny|warn|never
  synthetic:
    values:
      - {label: customer_api_key, type: synthetic_api_key}
  policy:
    mode: strict                  # strict | warn_only (warn_only downgrades deny to warn)
    default_action: deny          # applied to unmatched non-approved observations
    rules:
      - {id: R1, data: customer_api_key, destination: application_logs, action: deny, severity: high,
         scenario: prevent-secret-logging, remediation: "...", reason: "..."}   # id/severity/scenario/remediation/reason optional
  providers:
    chat: {type: mock, behavior: safe}   # named provider configs, see providers module
  scenarios:
    - name: prevent-secret-logging
      category: logging           # logging|network|ai_context|response|storage
      target: "mypkg.app:handle_login"   # module:callable, called as fn(**inputs[, provider=...])
      inputs: {api_key: "{{ customer_api_key }}", note: "hello"}   # "{{ label }}" substituted with raw value
      data: [customer_api_key]    # labels registered for this scenario (default: all)
      provider: chat              # optional provider config name; passed as kwarg `provider` if fn accepts it
      storage_paths: []           # explicit files/dirs to scan after the run
      expect_exception: false     # exceptions are always captured as error_report events
      approved_destinations: []   # extra destinations treated as approved for this scenario
  ```
  `data` entries in rules may be a label, a DataType value, or `"*"`; `destination` a Destination value or `"*"`.
* `policies.schema`: `PolicyConfig`, `Rule`. `policies.loader.compile_policy(policy: PolicyConfig, declared_labels: set[str],
  labels_to_types: dict[str, DataType]) -> PolicyEvaluator` raising `PolicyError` for: unknown destination, unknown
  label, duplicate rule ids, conflicting rules (same scenario+data+destination, different action), unknown scenario names
  (checked when scenario names are provided), invalid severity. Never silently drops a rule.
* `policies.evaluator.PolicyEvaluator` implements `PolicyEvaluatorProtocol`:
  `decide(scenario: str, value: SyntheticValue, event: Event) -> Decision`. Precedence: approved events
  (`event.approved` or destination `approved_test_input` or scenario `approved_destinations`) => ALLOW (rule_id None, reason
  says why). Else most specific rule wins: scenario-scoped > unscoped, then label > data_type > `*`, then destination exact >
  `*`. No rule => `default_action`. `mode: warn_only` turns DENY into WARN. Default severity: deny=medium (rules may override),
  warn=low. Remediation hints per destination are available via `rules.remediation_for(destination) -> str`.
* `core/analysis.py`: `analyze(scenario: str, events: Iterable[Event], registry, inspectors: Sequence[Inspector],
  evaluator, collector_dropped: int = 0) -> list[Finding]`: for each event run inspectors whose `destinations` contain
  the event destination; for each match get the value, ask evaluator; ALLOW => no finding; DENY/WARN => Finding.
  Category derived from destination: application_logs/error_report=>logging, http_request=>network,
  ai_request=>ai_context, ai_output=>response, storage=>storage. Finding id `SS-<LOG|NET|CTX|RSP|STO|REG>-<NNN>`
  sequential per run. Dedup key (scenario, value_id, destination, component, location) merges into `occurrences`.
  Streaming: events with `metadata["aggregated"] is True` are analyzed too; if a per-chunk finding already exists
  for the same value+component, do not add a second finding for the aggregate. Evidence via
  `evidence.redaction.build_evidence`. `confidence` = "exact" if variant == raw else "normalized".
* `core/runner.py`: `run_config(cfg: SecretsiftConfig, *, config_path: Path | None = None, offline_override: bool | None = None,
  category_filter: str | None = None) -> Report`. Per scenario: fresh run_id, fresh registry + collector; generate values via
  `synthetic.generator`; record the substituted inputs as `approved_test_input` events; open
  `instrumentation.Instrumentation(...)`; import target (restore `sys.path` after), build provider via
  `providers.create_provider` wrapped by `providers.instrumented.InstrumentedProvider` if requested; call target; capture
  any exception as an `error_report` event (message + traceback text) and, if `expect_exception` is false, ALSO mark the
  scenario `ERRORED` only if the exception is not a privacy matter (i.e. ScenarioStatus is derived: findings take priority;
  otherwise errored); snapshot storage; analyze; always `registry.clear()` and collector clear in a `finally`
  (cleanup lifecycle). Status: any DENY finding => FAILED; else any WARN => WARNED; else error => ERRORED; else PASSED.
  Assemble `Report` (summary counts, `Coverage` with inspectors active, destinations actually observed, offline flag and
  limitations list: uninstrumented services, hosted-provider note, kernel-level traffic, subprocesses).
  Import of target uses `importlib` with the user's `sys_path`; target errors are `ScenarioError` with redacted message.
* `core/scenario.py`: `ScenarioSpec`, template substitution `render_inputs(inputs, values_by_label)` (only `{{ label }}`;
  unknown label => ConfigError; deep over dict/list/str). `core/context.py`: `RunContext` dataclass. `core/lifecycle.py`:
  `Lifecycle` context manager guaranteeing cleanup order.
* `assertions/privacy.py`: `assert_no_findings(findings, *, allow_warn=False)` raising `AssertionError` with a redacted
  multi-line message. `assertions/regression.py`: `compare_to_baseline(old: Report, new: Report) -> BaselineDiff`
  (dataclass: `new`, `fixed`, `unchanged` finding lists; identity key = scenario+category+destination+component+value label
  +rule_id; value_id is run-specific and must NOT be part of identity) and `regression_findings(diff) -> list[Finding]`
  re-labelled `Category.REGRESSION`.

### C. instrumentation + inspectors  (owner: agent C)
Files: `instrumentation/{__init__,capture,logcapture,stdio,httpguard,storage,sockets}.py`,
`inspectors/{__init__,base,logs,http,errors,ai_requests,ai_outputs,storage}.py`,
`integrations/{__init__,httpx_transport}.py`, tests `tests/unit/instrumentation/`, `tests/unit/inspectors/`,
`tests/integration/test_instrumentation_*.py`, `tests/security/test_offline_guard.py`.
* `instrumentation.Instrumentation(collector: EventCollector, *, offline: bool, network_allowlist: Sequence[str] = (),
  storage_paths: Sequence[Path] = (), capture_stdio: bool = True, component_prefix: str = "app")` — context manager
  (re-entrant safe, restores everything on exit even on exception). Methods: `provider_traffic(provider_name: str)`
  context manager; `snapshot_storage() -> None` (emit `storage` events for explicit paths only).
  Installs: (1) `logging` handler on the root logger at level 1 capturing formatted message + `exc_info` text +
  `extra` fields as `application_logs` (component = logger name, location = `file:line`); (2) stdout/stderr tee as
  `application_logs` component `stdout`/`stderr` (still forwarding to the real stream); (3) `http.client` guard: patch
  `HTTPConnection.putrequest/putheader/endheaders/send` (or `request`) so every outbound request emits `http_request`
  events with `metadata.part` in {url, headers, body}; sensitive header values (Authorization, X-Api-Key, X-Goog-Api-Key,
  Cookie, Proxy-Authorization) are replaced by `[HEADER-REDACTED]` BEFORE the event is created; requests to hosts that are
  not loopback (offline) or not in allowlist (online) raise `OfflineViolationError` BEFORE any bytes are sent; this covers
  urllib, requests and anything on http.client; (4) `socket.socket.connect` guard (offline: block non-loopback);
  (5) while inside `provider_traffic(name)`, the HTTP body event is emitted with `approved=True` and
  `metadata.provider=name` (URL and headers events remain unapproved so a secret in a URL or header is still flagged).
  Patches are process-global, guarded by a lock and reference count; nested use must not double-wrap.
  Python warnings and `sys.excepthook` are out of scope.
* `instrumentation.storage`: explicit-path scanner, never follows symlinks out of the given root, skips files > 5 MB and
  binary-looking files (records skipped count in metadata), each file => one `storage` event with `metadata.path`
  (relative) and component `storage:<name>`. In-memory adapter `DictStorageAdapter(mapping)` for caches.
* `inspectors.*`: concrete `Inspector` subclasses: `LogInspector` (application_logs), `ErrorInspector` (error_report),
  `HttpInspector` (http_request; also inspects `metadata["url"]`/header strings that are in payload), `AIRequestInspector`
  (ai_request), `AIOutputInspector` (ai_output, handles aggregated streaming events), `StorageInspector` (storage).
  Each uses `registry.find(event.payload)`. `inspectors.default_inspectors() -> list[Inspector]`; names are stable
  (`logs`, `errors`, `http`, `ai_requests`, `ai_outputs`, `storage`). `inspectors.base.PayloadInspector` shared base.
* `integrations/httpx_transport.py` (optional dependency, lazy import): `SecretsiftTransport(wrapped, collector,
  *, offline, allowlist=(), provider_name=None)` emitting the same http_request events; raise `OfflineViolationError`
  for blocked hosts. Unit tests must `skipUnless(httpx importable)`.

### D. providers  (owner: agent D)
Files: `providers/{__init__,base,mock,transport,openai_compatible,ollama,llama_cpp,openai,anthropic,gemini,instrumented,registry}.py`,
tests `tests/unit/providers/`.
* `base`: pydantic models `Message(role, content)`, `ProviderRequest(messages, model, system: str|None, params: dict)`,
  `ProviderResponse(text, model, metadata)`; ABC `Provider` with `name`, `requires_network: bool`,
  `complete(req) -> ProviderResponse`, `stream(req) -> Iterator[str]`, `status() -> ProviderStatus`
  (`configured: bool`, `detail: str`, never includes credential values; only whether the env var is set).
* `transport.py`: `Transport` protocol + `UrllibTransport` (stdlib `http.client`/`urllib.request`, timeout, size caps, no
  redirects to other hosts, JSON helpers, SSE and NDJSON line iterators). Everything network goes through it so tests inject
  `FakeTransport`. Provider errors: build `ProviderError` messages via `evidence.redaction.redact_credentials` and never
  include request bodies; provider exceptions include status code + sanitized server error text (also credential-redacted).
* `mock.MockProvider(behavior: "safe"|"echo"|"leaky_error"|"scripted", script: list[str] | None, chunk_size: int = 5, ...)`:
  deterministic, offline (`requires_network = False`); `echo` repeats the user message (demonstrates output leakage),
  `leaky_error` raises ProviderError containing the prompt text (demonstrates error leakage), streaming splits text into
  chunks (so cross-chunk leaks are testable).
* Real adapters, each implemented from the provider's documented wire format and unit-tested only with `FakeTransport`
  (no live calls): `openai_compatible` (base_url + `/chat/completions`, SSE `data:` lines, `[DONE]`), `openai`
  (subclass with default base `https://api.openai.com/v1`, key env `OPENAI_API_KEY`), `llama_cpp` (OpenAI-compatible, default
  `http://127.0.0.1:8080/v1`, no key), `ollama` (`/api/chat`, NDJSON stream, default `http://127.0.0.1:11434`, no key),
  `anthropic` (`https://api.anthropic.com/v1/messages`, headers `x-api-key`, `anthropic-version: 2023-06-01`, SSE
  `content_block_delta` text deltas, key env `ANTHROPIC_API_KEY`), `gemini`
  (`https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent`, stream via `:streamGenerateContent?alt=sse`,
  header `x-goog-api-key`, key env `GEMINI_API_KEY`). Keys are read from env at call time only, sent only in headers, never
  stored on repr/status. Document in each module docstring: "wire format implemented from public API docs; verify against
  current provider docs before relying on it" (do not claim live verification).
* `registry.py`: `create_provider(name_or_cfg: str | dict, config: Mapping[str, Any] | None = None) -> Provider`
  (cfg dict has `type`), `available_provider_types() -> list[str]`, `provider_statuses() -> list[tuple[str, ProviderStatus]]`.
* `instrumented.InstrumentedProvider(inner: Provider, collector: EventCollector, instrumentation: Instrumentation | None = None,
  component: str | None = None)`: same interface as Provider; `complete`/`stream` emit an `ai_request` event (system + each
  message rendered `role: content` + params JSON; metadata: provider, model), call the inner provider inside
  `instrumentation.provider_traffic(inner.name)` when given, then emit `ai_output` (full text) or for streams one `ai_output`
  per chunk (metadata `chunk_index`) plus one aggregated event (`metadata={"aggregated": True}`) after the stream ends; provider
  errors are emitted as `error_report` events (message only, redacted of credentials, but NOT of synthetic values) and re-raised.

### E. reporting  (owner: agent E)
Files: `reporting/{__init__,terminal,json_report,html_report,junit,diff,safe_io}.py`, tests `tests/unit/reporting/`,
`tests/security/test_report_escaping.py`.
* All reporters implement `contracts.Reporter`. `reporting.get_reporter(name) -> Reporter` for `terminal|json|html|junit`;
  `reporting.write_report(report, fmt, path) -> Path` using `safe_io` (create parent dirs, refuse to write through a symlink,
  atomic write via temp file + rename, file mode `0o600`).
* `terminal.TerminalReporter(color: bool | None = None)` plain ANSI, honors `NO_COLOR` and non-TTY, summary header, per-scenario
  status, per-finding block (id, category, severity, expected vs observed, component/location, redacted evidence, remediation),
  coverage + limitations footer. Pure stdlib.
* `json_report`: stable schema (`Report.model_dump(mode="json")` plus `"$schema": "secretsift-report/1"`), `dumps(report)`,
  `loads(text) -> Report` (validates schema_version, size limit, raises `ConfigError`).
* `html_report`: ONE self-contained `.html` (inline CSS, inline SVG charts, NO scripts, NO external resources, a restrictive
  `<meta http-equiv="Content-Security-Policy">`). Sections: header with run metadata, pass/fail summary donut (SVG), findings by
  category and by severity bar charts (SVG), scenario table, per-finding cards with redacted evidence, remediation, coverage and
  limitations. Every dynamic string passes `html.escape(quote=True)`. Accessible (semantic headings, alt/aria labels, sufficient
  contrast, works in dark mode via `prefers-color-scheme`), responsive at phone width.
* `junit`: JUnit XML (`testsuite` per run, `testcase` per scenario, `failure` per deny finding; warn => `system-out`; errored =>
  `error`), generated with `xml.etree.ElementTree` (escaping handled), no raw secrets.
* `diff`: `diff_reports(old: Report, new: Report) -> ReportDiff` (identity key = scenario+category+destination+component+data
  label... NOTE `Finding` has no label field: use scenario+category+destination+component+data_type+rule_id) and
  `render_diff(diff, color=None) -> str`. (Agent B has an equivalent `compare_to_baseline`; E's version is the CLI-facing one.)

### F. repository hygiene  (owner: agent F)
`README.md` placeholder is NOT allowed to stay: write the real README last-mile (agent H later finalizes). F writes:
`LICENSE` (full Apache-2.0 text), `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` (concise, Contributor-Covenant-style, own words),
`SECURITY.md` (private reporting process, scope, supported versions), `CHANGELOG.md` (Keep a Changelog, `0.1.0` unreleased),
`.gitignore`, `.editorconfig`, `.github/workflows/{tests,lint,typecheck,security}.yml` (matrix 3.11-3.13 x ubuntu/macos/windows for tests;
ruff; mypy strict; pip-audit + CodeQL-free simple secret check), `.github/ISSUE_TEMPLATE/{bug_report,feature_request,config}.yml`,
`.github/pull_request_template.md`, `.github/dependabot.yml`. Workflows must use pinned major versions of official actions,
least-privilege `permissions:`, and run: `python -m pip install -e ".[dev]"` then the real commands
(`python -m unittest discover -s tests -t . -q`, `pytest`, `ruff check`, `ruff format --check`, `mypy`).

### G. cli + sdk + pytest plugin  (stage 2)   H. examples + docs  (stage 2)
Defined later against the real implemented APIs.

## 4. Finding IDs, exit codes, limitations text

* Exit codes: 0 clean (or only warnings when `fail_on: deny`), 1 deny findings (or warn findings when `fail_on: warn`),
  2 scenario errors only, 3 invalid config / usage.
* Standard limitation strings (use verbatim in `Coverage.limitations`): see `core/runner.py` (agent B owns the list).

## 5. Definition of done per module

Implemented, typed, unit-tested (positive + negative + edge + security cases), no network, passes the unittest command above,
no stubs, no unused code, consistent with this document.
