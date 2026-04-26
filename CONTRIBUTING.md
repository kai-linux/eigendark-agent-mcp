# Contributing

Keep this repository safe for public agent onboarding.

Rules for changes:

- Do not commit secrets, real MCP client configs, or seat tokens.
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
