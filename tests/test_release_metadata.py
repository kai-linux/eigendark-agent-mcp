from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts/check_release_metadata.py"
SPEC = importlib.util.spec_from_file_location("check_release_metadata", SCRIPT_PATH)
assert SPEC is not None
assert SPEC.loader is not None
metadata = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(metadata)


def _pypi_document(files: dict[str, bytes]) -> dict[str, object]:
    urls = []
    for filename, content in files.items():
        urls.append(
            {
                "filename": filename,
                "packagetype": "bdist_wheel" if filename.endswith(".whl") else "sdist",
                "digests": {"sha256": hashlib.sha256(content).hexdigest()},
                "url": f"https://files.pythonhosted.org/packages/safe/{filename}",
                "yanked": False,
            }
        )
    return {
        "info": {
            "version": "0.4.0",
            "description": f"<!-- mcp-name: {metadata.EXPECTED_NAME} -->",
        },
        "urls": urls,
    }


def test_pypi_verification_matches_artifacts_and_attests(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    files = {
        "eigendark_agent_mcp-0.4.0-py3-none-any.whl": b"wheel-content",
        "eigendark_agent_mcp-0.4.0.tar.gz": b"sdist-content",
    }
    for filename, content in files.items():
        (tmp_path / filename).write_bytes(content)
    monkeypatch.setattr(metadata, "get_json", lambda url: _pypi_document(files))
    calls: list[list[str]] = []

    def fake_run(command, *, check, timeout):  # noqa: ANN001, ANN202
        assert check is True
        assert timeout == 120
        calls.append(command)

    monkeypatch.setattr(metadata.subprocess, "run", fake_run)
    metadata.check_pypi("0.4.0", dist_dir=tmp_path, verify_attestations=True)

    assert len(calls) == 2
    assert all(metadata.EXPECTED_REPOSITORY in command for command in calls)


def test_pypi_verification_rejects_digest_and_origin_changes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    filename = "eigendark_agent_mcp-0.4.0-py3-none-any.whl"
    files = {filename: b"expected", "eigendark_agent_mcp-0.4.0.tar.gz": b"sdist"}
    for local_name, content in files.items():
        (tmp_path / local_name).write_bytes(content)
    (tmp_path / filename).write_bytes(b"tampered")
    document = _pypi_document(files)
    monkeypatch.setattr(metadata, "get_json", lambda url: document)

    with pytest.raises(ValueError, match="digest"):
        metadata.check_pypi("0.4.0", dist_dir=tmp_path)

    (tmp_path / filename).write_bytes(files[filename])
    document["urls"][0]["url"] = "https://example.invalid/artifact.whl"
    with pytest.raises(ValueError, match="trusted origin"):
        metadata.check_pypi("0.4.0", dist_dir=tmp_path, verify_attestations=True)


def test_registry_verification_requires_active_expected_package(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry = {
        "server": {
            "name": metadata.EXPECTED_NAME,
            "version": "0.4.0",
            "packages": [
                {
                    "registryType": "pypi",
                    "identifier": metadata.EXPECTED_PACKAGE,
                    "version": "0.4.0",
                }
            ],
        },
        "_meta": {"io.modelcontextprotocol.registry/official": {"status": "active"}},
    }
    document = {"servers": [entry]}
    monkeypatch.setattr(metadata, "get_json", lambda url: document)
    metadata.check_registry("0.4.0")

    entry["server"]["packages"][0]["identifier"] = "wrong-package"
    with pytest.raises(ValueError, match="MCP Registry"):
        metadata.check_registry("0.4.0")
