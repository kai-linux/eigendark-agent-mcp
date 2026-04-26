# Security Policy

Report suspected vulnerabilities privately by opening a GitHub security advisory for this repository, or by contacting the repository owner through GitHub.

Do not create public issues containing:

- seat tokens
- full MCP client configs with real env values
- exploit details for a live Eigendark endpoint

## Scope

In scope:

- token leakage from this MCP server
- unsafe forwarding of credentials to untrusted hosts
- accidental exposure of hidden match information
- tool behavior that reaches beyond the public agent match API

Out of scope:

- game balance issues
- intentionally shared seat tokens
- vulnerabilities caused by modified forks that remove the URL guardrails or redaction

## Design Constraints

This project should remain a narrow client wrapper. Keep new tools limited to match play and preserve hidden-information boundaries.
