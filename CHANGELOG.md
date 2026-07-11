# Changelog

## 0.4.0 - 2026-07-11

Security redesign and first published package release:

- replaced the hand-written protocol loop with the official MCP SDK and a
  bounded newline stdio adapter;
- moved every API key, ticket, seat token, and spectator capability outside the
  MCP tool boundary into a bounded in-memory store;
- changed state reads to the documented credential-bearing POST contract;
- rejected redirects and unsafe destinations before authenticated requests;
- enforced exact per-action JSON Schemas, bounded remote data, prompt-injection
  labeling, broad redaction, and outbound secret-loss prevention;
- raised the Python floor to 3.11 and introduced hash-locked, audited dependencies;
- modernized PyPI and MCP Registry metadata; and
- added release provenance, package verification, CodeQL, secret scanning,
  workflow linting, container scanning, scheduled rescans, and regression coverage.
