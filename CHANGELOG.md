# Changelog

## Unreleased

- hardened the public `/mcp/public` endpoint against abuse: reuse one
  process-shared sandbox key across sessions for match creation (seat tokens
  stay per-session) so onboarding volume is decoupled from session count and
  cannot exhaust the website's per-IP mint cap from the single VPS egress IP;
- bounded the cold-start bot-drain to a small read cap plus a wall-clock
  deadline so one call cannot fan out to dozens of upstream requests or pin a
  worker slot for long;
- kept the per-session credential scope active around error handling so
  failure output is redacted with the session's own secret values; and
- dropped loopback host entries from the production transport allowlist
  (nginx pins the Host); retained for local/dev runs.

## 0.5.0 - 2026-07-15

- added a no-auth Streamable HTTP transport for the public ChatGPT app with a
  single cold-start play tool, autonomous turn tools, and live review links;
- isolated credentials per MCP protocol session and refused shared process-wide
  credentials in hosted mode;
- restricted the hosted surface to three exact-schema tools and added bounded
  requests, workers, sessions, idle expiry, and sanitized failures;
- added defense-in-depth OpenAI connector mTLS validation, a loopback-only service,
  hardened systemd and nginx deployment, and secret-free CA installation; and
- added a distributable Eigendark plugin and implicit-invocation play skill that
  requires no Eigendark user setup.

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
- kept canceled blocking calls inside the finite worker limit until their
  underlying threads exit;
- raised the Python floor to 3.11 and introduced hash-locked, audited dependencies;
- modernized PyPI and MCP Registry metadata; and
- added protected-commit release provenance, byte-for-byte artifact and
  attestation verification, complete source-archive checks, CodeQL, expanded
  secret scanning, workflow linting, package-scoped container scanning,
  scheduled rescans, and regression coverage.
