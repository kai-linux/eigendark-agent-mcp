#!/usr/bin/env python3
"""Fail when package, registry, source, and documentation metadata diverge."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
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
EXPECTED_REPOSITORY = "https://github.com/kai-linux/eigendark-agent-mcp"
VERSION_PATTERN = re.compile(r'^__version__\s*=\s*["\']([^"\']+)["\']\s*$', re.MULTILINE)
MCP_PIN = re.compile(r"^mcp==([0-9]+(?:\.[0-9]+){2})$")


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

    dependencies = project.get("dependencies", [])
    mcp_dependencies = [
        item for item in dependencies if isinstance(item, str) and item.startswith("mcp")
    ]
    if len(mcp_dependencies) != 1 or MCP_PIN.fullmatch(mcp_dependencies[0]) is None:
        failures.append("the published MCP SDK dependency must use one exact three-part version")
    elif not re.search(
        rf"^mcp=={re.escape(MCP_PIN.fullmatch(mcp_dependencies[0]).group(1))}\s",
        (ROOT / "requirements-runtime.lock").read_text(encoding="utf-8"),
        re.MULTILINE,
    ):
        failures.append("the exact MCP SDK dependency does not match the runtime lock")

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
    if dockerfile.count("pip install --only-binary=:all: --require-hashes") != 2:
        failures.append("Docker build and runtime lock installs must reject source distributions")
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


def check_pypi(
    version: str,
    *,
    dist_dir: Path | None = None,
    verify_attestations: bool = False,
) -> None:
    document = get_json(f"https://pypi.org/pypi/{EXPECTED_PACKAGE}/{version}/json")
    info = document.get("info", {})
    raw_urls = document.get("urls", [])
    urls = (
        [item for item in raw_urls if isinstance(item, dict)] if isinstance(raw_urls, list) else []
    )
    if not isinstance(info, dict) or info.get("version") != version or not urls:
        raise ValueError(f"PyPI does not contain a complete {EXPECTED_PACKAGE} {version} release")
    if not any(item.get("packagetype") == "bdist_wheel" for item in urls):
        raise ValueError("PyPI release has no wheel")
    if not any(item.get("packagetype") == "sdist" for item in urls):
        raise ValueError("PyPI release has no source distribution")
    if any(item.get("yanked") is True for item in urls):
        raise ValueError("PyPI release contains a yanked distribution")
    description = info.get("description", "")
    if f"mcp-name: {EXPECTED_NAME}" not in description:
        raise ValueError("Published PyPI description is missing the MCP ownership marker")

    by_filename = {
        item.get("filename"): item for item in urls if isinstance(item.get("filename"), str)
    }
    if len(by_filename) != len(urls):
        raise ValueError("PyPI release contains an invalid or duplicate filename")
    if dist_dir is not None:
        local_files = sorted(
            path
            for path in dist_dir.iterdir()
            if path.is_file() and (path.suffix == ".whl" or path.name.endswith(".tar.gz"))
        )
        if not local_files:
            raise ValueError("the release artifact directory contains no distributions")
        if {path.name for path in local_files} != set(by_filename):
            raise ValueError("the PyPI and locally built distribution sets differ")
        for path in local_files:
            digests = by_filename[path.name].get("digests", {})
            expected = digests.get("sha256") if isinstance(digests, dict) else None
            with path.open("rb") as stream:
                actual = hashlib.file_digest(stream, "sha256").hexdigest()
            if not isinstance(expected, str) or actual != expected:
                raise ValueError(f"PyPI digest does not match the built artifact {path.name}")

    if verify_attestations:
        for item in urls:
            url = _trusted_pypi_file_url(item)
            try:
                subprocess.run(  # noqa: S603 - fixed executable and validated URL
                    [
                        sys.executable,
                        "-m",
                        "pypi_attestations",
                        "verify",
                        "pypi",
                        "--repository",
                        EXPECTED_REPOSITORY,
                        url,
                    ],
                    check=True,
                    timeout=120,
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                raise ValueError("PyPI publisher attestation verification failed") from exc


def _trusted_pypi_file_url(item: dict[str, Any]) -> str:
    value = item.get("url")
    if not isinstance(value, str):
        raise ValueError("PyPI distribution is missing its file URL")
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError as exc:
        raise ValueError("PyPI distribution has an invalid file URL") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname != "files.pythonhosted.org"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("PyPI distribution file URL left the trusted origin")
    return value


def check_registry(version: str) -> None:
    query = urllib.parse.urlencode({"search": EXPECTED_NAME})
    document = get_json(f"https://registry.modelcontextprotocol.io/v0.1/servers?{query}")
    entries = document.get("servers", [])
    for entry in entries if isinstance(entries, list) else []:
        candidate = entry.get("server", entry) if isinstance(entry, dict) else {}
        if not isinstance(candidate, dict):
            continue
        packages = candidate.get("packages", [])
        package_matches = any(
            isinstance(package, dict)
            and package.get("registryType") == "pypi"
            and package.get("identifier") == EXPECTED_PACKAGE
            and package.get("version") == version
            for package in packages
            if isinstance(packages, list)
        )
        if (
            candidate.get("name") == EXPECTED_NAME
            and candidate.get("version") == version
            and package_matches
        ):
            official = (
                entry.get("_meta", {}).get("io.modelcontextprotocol.registry/official", {})
                if isinstance(entry, dict)
                else {}
            )
            if isinstance(official, dict) and official.get("status") == "active":
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
    parser.add_argument("--dist-dir", type=Path)
    parser.add_argument("--verify-pypi-attestations", action="store_true")
    args = parser.parse_args(argv)
    if (args.dist_dir is not None or args.verify_pypi_attestations) and not args.check_pypi:
        parser.error("--dist-dir and --verify-pypi-attestations require --check-pypi")
    try:
        version, _ = load_local_metadata()
        if args.check_pypi:
            check_pypi(
                version,
                dist_dir=args.dist_dir,
                verify_attestations=args.verify_pypi_attestations,
            )
        if args.check_registry:
            check_registry(version)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"release metadata check failed: {exc}", file=sys.stderr)
        return 1
    print(f"release metadata is consistent for {EXPECTED_PACKAGE} {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
