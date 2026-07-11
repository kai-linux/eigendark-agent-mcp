#!/usr/bin/env python3
"""Require every Trivy suppression to be specific, justified, and short lived."""

from __future__ import annotations

import re
import sys
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
IGNORE_FILE = ROOT / ".trivyignore.yaml"
CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
DEBIAN_PURL = re.compile(r"^pkg:deb/debian/[A-Za-z0-9.+-]+@[^?\s]+\?[^\s]+$")
MAX_EXCEPTION_LIFETIME = timedelta(days=45)


def main() -> int:
    document = yaml.safe_load(IGNORE_FILE.read_text(encoding="utf-8"))
    entries = document.get("vulnerabilities") if isinstance(document, dict) else None
    failures: list[str] = []
    seen: set[str] = set()
    today = datetime.now(tz=UTC).date()
    if not isinstance(entries, list):
        failures.append(".trivyignore.yaml must contain a vulnerabilities list")
        entries = []
    for entry in entries:
        if not isinstance(entry, dict):
            failures.append("every vulnerability exception must be an object")
            continue
        identifier = entry.get("id")
        statement = entry.get("statement")
        expiry = entry.get("expired_at")
        purls = entry.get("purls")
        if not isinstance(identifier, str) or not CVE.fullmatch(identifier):
            failures.append(f"invalid vulnerability ID: {identifier!r}")
            continue
        if identifier in seen:
            failures.append(f"duplicate vulnerability exception: {identifier}")
        seen.add(identifier)
        if not isinstance(statement, str) or len(statement.strip()) < 80:
            failures.append(f"{identifier} needs a meaningful risk and reachability statement")
        if not isinstance(purls, list) or not purls:
            failures.append(f"{identifier} must be scoped to exact Debian package URLs")
        elif any(not isinstance(purl, str) for purl in purls):
            failures.append(f"{identifier} package URLs must all be strings")
        elif len(purls) != len(set(purls)):
            failures.append(f"{identifier} contains duplicate package URLs")
        else:
            for purl in purls:
                if (
                    not DEBIAN_PURL.fullmatch(purl)
                    or "arch=" not in purl
                    or "distro=debian-" not in purl
                    or "*" in purl
                ):
                    failures.append(f"{identifier} has an unscoped package URL: {purl!r}")
        if not isinstance(expiry, date):
            failures.append(f"{identifier} needs a YAML date in expired_at")
        elif expiry < today:
            failures.append(f"{identifier} expired on {expiry.isoformat()}")
        elif expiry - today > MAX_EXCEPTION_LIFETIME:
            failures.append(f"{identifier} expiry exceeds the 45-day review window")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"{len(entries)} documented Trivy exceptions are current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
