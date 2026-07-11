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


def main() -> int:
    failures = [
        failure for path in sorted(WORKFLOWS.glob("*.yml")) for failure in check_workflow(path)
    ]
    if not list(WORKFLOWS.glob("*.yml")):
        failures.append("no GitHub Actions workflows found")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("workflow supply-chain invariants pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
