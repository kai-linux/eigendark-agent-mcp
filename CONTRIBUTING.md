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
uv venv --seed --python 3.12 .venv
.venv/bin/python -m pip install --only-binary=:all: --require-hashes -r requirements-dev.lock
.venv/bin/python -m pip install --no-deps --no-build-isolation -e .
.venv/bin/ruff check src tests scripts
.venv/bin/ruff format --check src tests scripts
.venv/bin/pytest --cov=eigendark_agent_mcp
.venv/bin/bandit -c pyproject.toml -r src
.venv/bin/pip-audit --require-hashes -r requirements-runtime.lock
.venv/bin/python -m build --no-isolation
.venv/bin/twine check dist/*
```

Dependencies are hash-locked. When `pyproject.toml` changes, regenerate all
three lock files with the exact `uv` version recorded in CI and commit the
result. Anchor universal resolution to the minimum supported interpreter so
Python-conditional transitive dependencies are retained:

```bash
uv pip compile --universal --python-version 3.11 --generate-hashes pyproject.toml --output-file requirements-runtime.lock
uv pip compile --universal --python-version 3.11 --generate-hashes --extra dev pyproject.toml --output-file requirements-dev.lock
uv pip compile --universal --python-version 3.11 --generate-hashes requirements-build.in --output-file requirements-build.lock
```

CI recompiles the locks, rejects drift, and installs the development lock into
clean Python 3.11, 3.12, 3.13, and 3.14 runners. Do not use an already-populated
virtual environment as evidence that a lock is complete.

Every security fix must include a regression test for the violated invariant
and, where applicable, a workflow or metadata check that prevents recurrence.
The control-to-gate map lives in [docs/SECURITY_CONTROLS.md](docs/SECURITY_CONTROLS.md).

If a secret reaches a commit, comment, CI log, or attachment, revoke it and
follow the exposure procedure in [SECURITY.md](SECURITY.md). Do not repost it.
