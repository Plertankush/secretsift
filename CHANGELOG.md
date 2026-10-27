# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - Unreleased

### Added

- Deterministic synthetic secret generation with per-run markers and variant-aware matching
  (case, URL, base64, hex, JSON-escaped, whitespace).
- Policy engine with allow, warn and deny decisions, rule specificity and warn-only mode.
- Scenario runner with instrumentation for logging, stdout/stderr, outbound HTTP, sockets and
  explicitly configured storage, plus an offline guard.
- Provider adapters: mock, OpenAI-compatible, OpenAI, Anthropic, Gemini, Ollama and llama.cpp,
  tested only against fake transports.
- Terminal, JSON, self-contained HTML and JUnit XML reports with redacted evidence.
- Baseline comparison for regression detection.
- Repository hygiene: Apache-2.0 license, contribution and security docs, CI workflows.

[Unreleased]: https://github.com/plertankush/secretsift/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/plertankush/secretsift/releases/tag/v0.1.0
