#!/usr/bin/env python3
"""Enforce baseline GitHub Actions supply-chain invariants without network access."""

from __future__ import annotations

import re
import sys
import tomllib
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
    if re.search(r"^\s*run:\s+.*--only-binary=:all:", text, re.MULTILINE):
        failures.append("YAML-sensitive :all: install options must use a block scalar")
    for use in USES.findall(text):
        if use.startswith("./"):
            continue
        if "@" not in use or not FULL_SHA.fullmatch(use.rsplit("@", 1)[1]):
            failures.append(f"action is not pinned to a full commit SHA: {use}")
    checkout_count = len(re.findall(r"uses:\s*actions/checkout@", text))
    isolation_count = len(re.findall(r"persist-credentials:\s*false", text))
    if isolation_count < checkout_count:
        failures.append("every checkout must set persist-credentials: false")
    for line in text.splitlines():
        if (
            "pip install" in line
            and "--require-hashes" in line
            and "--only-binary=:all:" not in line
        ):
            failures.append("hash-locked installs must reject source distributions")
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
        if (
            "python -m pip install --only-binary=:all: --require-hashes -r requirements-dev.lock"
        ) not in ci:
            failures.append(
                ".github/workflows/ci.yml: clean test jobs must install the hashed lock"
            )
        if "pip-audit --require-hashes -r requirements-dev.lock" not in ci:
            failures.append(".github/workflows/ci.yml: development dependencies must be audited")
        if "python scripts/check_distribution.py dist" not in ci:
            failures.append(".github/workflows/ci.yml: built distributions must be inspected")
        for secret_scan_invariant in (
            "gitleaks/gitleaks-action@",
            "fetch-depth: 0",
        ):
            if secret_scan_invariant not in ci:
                failures.append(f".github/workflows/ci.yml: missing {secret_scan_invariant!r}")

    gitleaks_path = ROOT / ".gitleaks.toml"
    if not gitleaks_path.is_file():
        failures.append(".gitleaks.toml: required secret policy is missing")
    else:
        gitleaks = gitleaks_path.read_text(encoding="utf-8")
        gitleaks_document = tomllib.loads(gitleaks)
        rules = {
            rule.get("id"): rule
            for rule in gitleaks_document.get("rules", [])
            if isinstance(rule, dict)
        }
        for prefix in ("ed_", "mmt_", "seat_", "review_", "spectator_"):
            if prefix not in gitleaks:
                failures.append(f".gitleaks.toml: missing Eigendark prefix {prefix!r}")
        secret_canaries = (
            ("eigendark-api-key", "ed_" + "4f7a9c2e6b1d8f0a"),
            ("eigendark-capability", "mmt_" + "4f7a9c2e6b1d8f0a"),
            ("eigendark-capability", "seat_" + "4f7a9c2e6b1d8f0a"),
            ("eigendark-capability", "review_" + "4f7a9c2e6b1d8f0a"),
            ("eigendark-capability", "spectator_" + "4f7a9c2e6b1d8f0a"),
        )
        for rule_id, canary in secret_canaries:
            rule = rules.get(rule_id, {})
            pattern = rule.get("regex") if isinstance(rule, dict) else None
            if not isinstance(pattern, str) or re.search(pattern, canary) is None:
                failures.append(f".gitleaks.toml: {rule_id} does not detect its canary")
                continue
            for allowlist in rule.get("allowlists", []):
                if not isinstance(allowlist, dict):
                    continue
                for allow_pattern in allowlist.get("regexes", []):
                    if isinstance(allow_pattern, str) and re.search(allow_pattern, canary):
                        failures.append(f".gitleaks.toml: {rule_id} broadly allowlists its canary")

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

    publish_path = WORKFLOWS / "publish.yml"
    if not publish_path.is_file():
        failures.append(".github/workflows/publish.yml: required workflow is missing")
    else:
        publish = publish_path.read_text(encoding="utf-8")
        release_invariants = (
            "ref: ${{ github.sha }}",
            'git merge-base --is-ancestor "$GITHUB_SHA" refs/remotes/origin/main',
            "--verify-pypi-attestations",
            "--dist-dir dist",
            "python scripts/check_distribution.py dist",
            "attestations: true",
            "id-token: write",
        )
        for invariant in release_invariants:
            if invariant not in publish:
                failures.append(f".github/workflows/publish.yml: missing {invariant!r}")
        if publish.count("ref: ${{ github.sha }}") != 3:
            failures.append(
                ".github/workflows/publish.yml: every source checkout must use event SHA"
            )
        if publish.count("id-token: write") != 2:
            failures.append(
                ".github/workflows/publish.yml: only both publication jobs may mint OIDC tokens"
            )
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
