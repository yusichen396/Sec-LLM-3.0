# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 4.0.x   | :white_check_mark: |
| < 4.0   | :x: |

## Reporting a Vulnerability

Please **do not** open a public issue for security problems.

- Email the maintainers with the subject `[SECURITY] Sec-LLM`, or use GitHub's
  private "Report a vulnerability" advisory flow on this repository.
- Include: affected version/commit, deployment mode (local/cloud, `ENV_MODE`),
  reproduction steps, observed impact, and any proof-of-concept you can share.
- You can expect an initial acknowledgement within 5 business days and a status
  update at least every 14 days until the report is resolved.

We will tell you whether the report is accepted, ask for clarification when
needed, and credit you in the release notes unless you prefer to stay anonymous.

## Scope notes

- The agent executes security tooling. Only scan systems you are authorised to
  test; `AGENT_ALLOWED_TARGETS` and `AGENT_ALLOW_PRIVATE_TARGETS` are admission
  controls, **not** network isolation. Restrict egress at the network layer.
- Tool output, retrieved documents and email bodies are untrusted input and are
  treated as data by the prompt-injection guards.
- Docker sandbox escape, arbitrary file read/write, prompt-injection bypass,
  authentication/authorization bypass, and SSRF through the browser tools are all
  in scope.
