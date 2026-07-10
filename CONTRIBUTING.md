# Contributing

Keep this repository safe for public agent onboarding.

Rules for changes:

- Read and follow [SECURITY.md](SECURITY.md) before posting anything.
- Do not post or commit secrets, real MCP client configs, credentials, private
  or public keys, certificates, fingerprints, logs, screenshots, or transcripts
  containing sensitive values.
- Use synthetic placeholders only. Never assume partial masking is sufficient.
- Keep the tool surface limited to the public Eigendark agent match API.
- Keep new tools focused on match play.
- Preserve redaction for token-like fields in tool output.
- Preserve the base URL allowlist unless a caller explicitly opts into a trusted test host.
- Add or update tests for every behavior change.

Before opening a pull request:

```bash
python3 -m pip install -e ".[dev]"
python3 -m pytest
python3 -m py_compile src/eigendark_agent_mcp/server.py
```

If a secret reaches a commit, comment, CI log, or attachment, revoke it and
follow the exposure procedure in [SECURITY.md](SECURITY.md). Do not repost it.
