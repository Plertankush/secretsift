# Security Policy

## What secretsift is, and its threat model

secretsift is a developer tool for testing **your own software**. It plants **synthetic** secrets
(fake API keys, tokens, emails and similar), runs scenarios against code you point it at, and records
where those values surface: logs, stdout/stderr, exceptions, outbound HTTP, AI provider requests and
outputs, and storage paths you configure explicitly. A policy then decides allow, warn or deny.

Be clear about what that means:

- It uses synthetic data. It does not scan real user data or real credentials, and it is not a
  production monitor.
- It can only see flows it instruments. It **cannot see uninstrumented flows**, including other
  services, subprocesses, kernel-level or native-extension traffic, and anything a hosted AI
  provider does with data after receiving it.
- A clean report means the instrumented scenarios did not leak the planted values in the places
  observed. It is not proof that an application is free of leaks.
- Offline mode blocks non-loopback network access from within the Python process as a safety net.
  It is not a sandbox and does not contain malicious code. Only run targets you trust.
- Reports contain redacted evidence, but treat them as sensitive build artifacts anyway.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x (pre-release) | Yes, latest only |

## Reporting a vulnerability

Please report privately. **Do not open a public issue or pull request.**

1. Open the repository's **Security** tab and choose **Report a vulnerability** (GitHub private
   vulnerability reporting).
2. Describe the issue, affected version, impact and a minimal reproduction using synthetic data only.
3. Do not include real credentials or personal data.

We aim to acknowledge reports within 7 days and to share a fix plan or assessment within 30 days.
This is a volunteer-run project, so these are goals, not guarantees. We will credit reporters in the
advisory unless they prefer otherwise.

## In scope

- A raw synthetic value or real credential appearing in exceptions, logs, reports, `repr` or
  `model_dump`.
- Report output injection (for example unescaped content in HTML or XML reports).
- Unsafe file writes (symlink following, wrong permissions) and unsafe config or report parsing.
- A bypass of the offline guard that lets traffic leave when `offline: true`, within the documented
  scope above.
- Vulnerabilities in secretsift's own code or dependency handling.

## Out of scope

- Leaks in flows secretsift documents as uninstrumented.
- Vulnerabilities in the software under test, or in third-party AI providers.
- Issues requiring you to run untrusted targets or config files you chose to load.
