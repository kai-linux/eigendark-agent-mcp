#!/usr/bin/env python3
"""Enforce baseline GitHub Actions supply-chain invariants without network access."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
USES = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)
SUPPORTED_PYTHONS = ("3.11", "3.12", "3.13", "3.14")


def check_workflow(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    failures: list[str] = []
    if "pull_request_target:" in text:
        failures.append("pull_request_target is forbidden")
    if "permissions:" not in text:
        failures.append("explicit permissions are required")
    if "timeout-minutes:" not in text:
        failures.append("every workflow needs finite job timeouts")
    for use in USES.findall(text):
        if use.startswith("./"):
            continue
        if "@" not in use or not FULL_SHA.fullmatch(use.rsplit("@", 1)[1]):
            failures.append(f"action is not pinned to a full commit SHA: {use}")
    checkout_count = len(re.findall(r"uses:\s*actions/checkout@", text))
    isolation_count = len(re.findall(r"persist-credentials:\s*false", text))
    if isolation_count < checkout_count:
        failures.append("every checkout must set persist-credentials: false")
    return [f"{path.relative_to(ROOT)}: {failure}" for failure in failures]


def check_security_pipeline() -> list[str]:
    """Keep repository-specific security coverage from silently regressing."""
    failures: list[str] = []
    ci_path = WORKFLOWS / "ci.yml"
    codeql_path = WORKFLOWS / "codeql.yml"
    if not ci_path.is_file():
        failures.append(".github/workflows/ci.yml: required workflow is missing")
    else:
        ci = ci_path.read_text(encoding="utf-8")
        expected_matrix = (
            "python-version: [" + ", ".join(f'"{version}"' for version in SUPPORTED_PYTHONS) + "]"
        )
        if expected_matrix not in ci:
            failures.append(
                ".github/workflows/ci.yml: test matrix must cover Python "
                + ", ".join(SUPPORTED_PYTHONS)
            )
        if ci.count("uv pip compile --universal --python-version 3.11") != 3:
            failures.append(
                ".github/workflows/ci.yml: every lock must resolve from the Python 3.11 floor"
            )
        if "python -m pip install --require-hashes -r requirements-dev.lock" not in ci:
            failures.append(
                ".github/workflows/ci.yml: clean test jobs must install the hashed lock"
            )

    codeql_initializers = 0
    for path in WORKFLOWS.glob("*.yml"):
        codeql_initializers += path.read_text(encoding="utf-8").count(
            "uses: github/codeql-action/init@"
        )
    if codeql_initializers != 1:
        failures.append("workflows: exactly one advanced CodeQL initializer is required")
    if not codeql_path.is_file():
        failures.append(".github/workflows/codeql.yml: required workflow is missing")
    else:
        codeql = codeql_path.read_text(encoding="utf-8")
        required_codeql = (
            "language: [actions, python]",
            "languages: ${{ matrix.language }}",
            "queries: security-extended",
            "security-events: write",
        )
        for invariant in required_codeql:
            if invariant not in codeql:
                failures.append(f".github/workflows/codeql.yml: missing {invariant!r}")
    return failures


def main() -> int:
    failures = [
        failure for path in sorted(WORKFLOWS.glob("*.yml")) for failure in check_workflow(path)
    ]
    failures.extend(check_security_pipeline())
    if not list(WORKFLOWS.glob("*.yml")):
        failures.append("no GitHub Actions workflows found")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("workflow supply-chain invariants pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
