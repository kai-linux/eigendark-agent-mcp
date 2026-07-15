#!/usr/bin/env python3
"""Validate that release archives are bounded, safe, and operationally complete."""

from __future__ import annotations

import stat
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

MAX_ARCHIVE_FILES = 300
MAX_ARCHIVE_BYTES = 10 * 1024 * 1024
FORBIDDEN_LOCAL_NAMES = frozenset({".coverage", ".DS_Store", ".env", ".netrc", ".npmrc", ".pypirc"})
FORBIDDEN_LOCAL_SUFFIXES = (".key", ".p12", ".pem", ".pfx", ".pyc")

SDIST_REQUIRED = frozenset(
    {
        ".dockerignore",
        ".env.example",
        ".github/dependabot.yml",
        ".github/workflows/ci.yml",
        ".github/workflows/codeql.yml",
        ".github/workflows/publish.yml",
        ".github/workflows/security-scan.yml",
        ".gitleaks.toml",
        ".trivyignore.yaml",
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "Dockerfile",
        "LICENSE",
        "MANIFEST.in",
        "README.md",
        "SECURITY.md",
        "docs/SECURITY_CONTROLS.md",
        "pyproject.toml",
        "requirements-build.in",
        "requirements-build.lock",
        "requirements-dev.lock",
        "requirements-runtime.lock",
        "scripts/check_distribution.py",
        "scripts/check_release_metadata.py",
        "scripts/check_trivy_exceptions.py",
        "scripts/check_workflows.py",
        "server.json",
        "src/eigendark_agent_mcp/py.typed",
        "src/eigendark_agent_mcp/http_server.py",
        "src/eigendark_agent_mcp/server.py",
        "deploy/install-production.sh",
        "plugin/eigendark/.codex-plugin/plugin.json",
        "plugin/eigendark/.mcp.json",
        "plugin/eigendark/skills/play-eigendark/SKILL.md",
        "plugin/eigendark/skills/play-eigendark/agents/openai.yaml",
        "tests/conftest.py",
        "tests/test_release_metadata.py",
    }
)
WHEEL_REQUIRED = frozenset(
    {
        "eigendark_agent_mcp/py.typed",
        "eigendark_agent_mcp/http_server.py",
        "eigendark_agent_mcp/server.py",
        "eigendark_agent_mcp/tools.py",
    }
)


def _safe_name(name: str) -> bool:
    path = PurePosixPath(name)
    return (
        bool(name)
        and not name.startswith(("/", "\\"))
        and "\\" not in name
        and ".." not in path.parts
    )


def _validate_members(path: Path, members: list[tuple[str, int]], required: frozenset[str]) -> None:
    if not members or len(members) > MAX_ARCHIVE_FILES:
        raise ValueError(f"{path.name} contains an unsafe number of files")
    if sum(size for _, size in members) > MAX_ARCHIVE_BYTES:
        raise ValueError(f"{path.name} exceeds the uncompressed size limit")
    names = {name.rstrip("/") for name, _ in members}
    if any(not _safe_name(name) for name in names):
        raise ValueError(f"{path.name} contains an unsafe member path")

    def forbidden(name: str) -> bool:
        member = PurePosixPath(name)
        basename = member.name
        return (
            ".git" in member.parts
            or "__pycache__" in member.parts
            or basename in FORBIDDEN_LOCAL_NAMES
            or (basename.startswith(".env.") and basename != ".env.example")
            or basename.endswith(FORBIDDEN_LOCAL_SUFFIXES)
        )

    if any(forbidden(name) for name in names):
        raise ValueError(f"{path.name} contains a forbidden local file")
    missing = sorted(
        suffix
        for suffix in required
        if not any(name == suffix or name.endswith(f"/{suffix}") for name in names)
    )
    if missing:
        raise ValueError(f"{path.name} is missing required files: {', '.join(missing)}")


def check_sdist(path: Path) -> None:
    with tarfile.open(path, mode="r:gz") as archive:
        raw_members = archive.getmembers()
    if any(not (member.isfile() or member.isdir()) for member in raw_members):
        raise ValueError(f"{path.name} contains links or special files")
    _validate_members(
        path,
        [(member.name, member.size) for member in raw_members],
        SDIST_REQUIRED,
    )


def check_wheel(path: Path, version: str) -> None:
    dist_info = f"eigendark_agent_mcp-{version}.dist-info"
    required = WHEEL_REQUIRED | {
        f"{dist_info}/METADATA",
        f"{dist_info}/RECORD",
        f"{dist_info}/entry_points.txt",
    }
    with zipfile.ZipFile(path) as archive:
        raw_members = archive.infolist()
    for item in raw_members:
        mode = item.external_attr >> 16
        kind = stat.S_IFMT(mode)
        if kind and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise ValueError(f"{path.name} contains a link or special file")
    members = [(item.filename, item.file_size) for item in raw_members]
    _validate_members(path, members, frozenset(required))


def check_distributions(directory: Path, version: str) -> None:
    expected = {
        directory / f"eigendark_agent_mcp-{version}-py3-none-any.whl",
        directory / f"eigendark_agent_mcp-{version}.tar.gz",
    }
    actual = {path for path in directory.iterdir() if path.is_file()}
    if actual != expected:
        raise ValueError("dist must contain exactly the expected wheel and source archive")
    check_wheel(next(path for path in expected if path.suffix == ".whl"), version)
    check_sdist(next(path for path in expected if path.name.endswith(".tar.gz")))


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if len(argv) != 2:
        print("usage: check_distribution.py DIST_DIRECTORY VERSION", file=sys.stderr)
        return 2
    try:
        check_distributions(Path(argv[0]), argv[1])
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print(f"distribution check failed: {exc}", file=sys.stderr)
        return 1
    print(f"release distributions are complete for {argv[1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
