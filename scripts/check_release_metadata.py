#!/usr/bin/env python3
"""Fail when package, registry, source, and documentation metadata diverge."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_SCHEMA = "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"
EXPECTED_NAME = "io.github.kai-linux/eigendark-agent-mcp"
EXPECTED_PACKAGE = "eigendark-agent-mcp"
VERSION_PATTERN = re.compile(r'^__version__\s*=\s*["\']([^"\']+)["\']\s*$', re.MULTILINE)


def load_local_metadata() -> tuple[str, dict[str, Any]]:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    server = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
    source = (ROOT / "src/eigendark_agent_mcp/__init__.py").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    version = project["version"]
    failures: list[str] = []
    source_match = VERSION_PATTERN.search(source)
    source_version = source_match.group(1) if source_match else None
    package = server.get("packages", [{}])[0]

    equal_values = {
        "source __version__": source_version,
        "server version": server.get("version"),
        "server package version": package.get("version"),
    }
    for label, value in equal_values.items():
        if value != version:
            failures.append(f"{label} is {value!r}, expected {version!r}")

    if server.get("$schema") != EXPECTED_SCHEMA:
        failures.append("server.json does not use the current pinned registry schema")
    if server.get("name") != EXPECTED_NAME:
        failures.append("server.json name does not match the owned GitHub namespace")
    if package.get("registryType") != "pypi" or package.get("identifier") != EXPECTED_PACKAGE:
        failures.append("server.json does not identify the expected PyPI package")
    if package.get("runtimeHint") != "uvx":
        failures.append("server.json must advertise the uvx runtime")
    if len(server.get("description", "")) not in range(1, 101):
        failures.append("server.json description must contain 1-100 characters")
    repository = server.get("repository", {})
    if not str(repository.get("id", "")).isdigit():
        failures.append("server.json repository must contain the stable numeric GitHub ID")
    if f"mcp-name: {EXPECTED_NAME}" not in readme:
        failures.append("README is missing the PyPI MCP ownership marker")
    if readme.count(f"{EXPECTED_PACKAGE}=={version}") < 2:
        failures.append("README installation examples do not pin the current release")
    if f'org.opencontainers.image.version="{version}"' not in dockerfile:
        failures.append("Docker image version label does not match the package")
    if f'io.modelcontextprotocol.server.name="{EXPECTED_NAME}"' not in dockerfile:
        failures.append("Docker image is missing the MCP ownership label")
    for obsolete in ("setup.py", "setup.cfg", "smithery.yaml", "pytest.ini"):
        if (ROOT / obsolete).exists():
            failures.append(f"obsolete packaging file still exists: {obsolete}")
    for lockfile in (
        "requirements-build.lock",
        "requirements-dev.lock",
        "requirements-runtime.lock",
    ):
        text = (ROOT / lockfile).read_text(encoding="utf-8")
        if "--hash=sha256:" not in text:
            failures.append(f"{lockfile} is not hash locked")

    if failures:
        raise ValueError("\n".join(failures))
    return version, server


def check_pypi(version: str) -> None:
    document = get_json(f"https://pypi.org/pypi/{EXPECTED_PACKAGE}/{version}/json")
    info = document.get("info", {})
    urls = document.get("urls", [])
    if info.get("version") != version or not urls:
        raise ValueError(f"PyPI does not contain a complete {EXPECTED_PACKAGE} {version} release")
    if not any(item.get("packagetype") == "bdist_wheel" for item in urls if isinstance(item, dict)):
        raise ValueError("PyPI release has no wheel")
    description = info.get("description", "")
    if f"mcp-name: {EXPECTED_NAME}" not in description:
        raise ValueError("Published PyPI description is missing the MCP ownership marker")


def check_registry(version: str) -> None:
    query = urllib.parse.urlencode({"search": EXPECTED_NAME})
    document = get_json(f"https://registry.modelcontextprotocol.io/v0.1/servers?{query}")
    entries = document.get("servers", [])
    for entry in entries:
        candidate = entry.get("server", entry) if isinstance(entry, dict) else {}
        if candidate.get("name") == EXPECTED_NAME and candidate.get("version") == version:
            return
    raise ValueError(f"MCP Registry does not contain {EXPECTED_NAME} {version}")


def get_json(url: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "eigendark-release-check/0.4.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = response.read(2 * 1024 * 1024 + 1)
    except urllib.error.HTTPError as exc:
        raise ValueError(f"release verification endpoint returned HTTP {exc.code}") from exc
    if len(payload) > 2 * 1024 * 1024:
        raise ValueError("release verification response was too large")
    parsed = json.loads(payload)
    if not isinstance(parsed, dict):
        raise ValueError("release verification response was not an object")
    return parsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-pypi", action="store_true")
    parser.add_argument("--check-registry", action="store_true")
    args = parser.parse_args(argv)
    try:
        version, _ = load_local_metadata()
        if args.check_pypi:
            check_pypi(version)
        if args.check_registry:
            check_registry(version)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"release metadata check failed: {exc}", file=sys.stderr)
        return 1
    print(f"release metadata is consistent for {EXPECTED_PACKAGE} {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
