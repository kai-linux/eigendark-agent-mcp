from __future__ import annotations

import importlib.util
import io
import tarfile
import zipfile
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts/check_distribution.py"
SPEC = importlib.util.spec_from_file_location("check_distribution", SCRIPT_PATH)
assert SPEC is not None
assert SPEC.loader is not None
distribution = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(distribution)

VERSION = "0.4.0"


def _write_complete_archives(directory: Path) -> tuple[Path, Path]:
    wheel = directory / f"eigendark_agent_mcp-{VERSION}-py3-none-any.whl"
    dist_info = f"eigendark_agent_mcp-{VERSION}.dist-info"
    wheel_names = distribution.WHEEL_REQUIRED | {
        f"{dist_info}/METADATA",
        f"{dist_info}/RECORD",
        f"{dist_info}/entry_points.txt",
    }
    with zipfile.ZipFile(wheel, mode="w") as archive:
        for name in wheel_names:
            archive.writestr(name, b"safe")

    sdist = directory / f"eigendark_agent_mcp-{VERSION}.tar.gz"
    with tarfile.open(sdist, mode="w:gz") as archive:
        for suffix in distribution.SDIST_REQUIRED:
            content = b"safe"
            member = tarfile.TarInfo(f"eigendark_agent_mcp-{VERSION}/{suffix}")
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return wheel, sdist


def test_distribution_checker_accepts_complete_bounded_archives(tmp_path: Path) -> None:
    _write_complete_archives(tmp_path)
    distribution.check_distributions(tmp_path, VERSION)


def test_distribution_checker_rejects_traversal_and_links(tmp_path: Path) -> None:
    wheel, sdist = _write_complete_archives(tmp_path)
    with zipfile.ZipFile(wheel, mode="a") as archive:
        archive.writestr("../escape", b"unsafe")
    with pytest.raises(ValueError, match="unsafe member path"):
        distribution.check_wheel(wheel, VERSION)

    wheel, sdist = _write_complete_archives(tmp_path)
    with zipfile.ZipFile(wheel, mode="a") as archive:
        archive.writestr(".env", b"unsafe")
    with pytest.raises(ValueError, match="forbidden local file"):
        distribution.check_wheel(wheel, VERSION)

    sdist.unlink()
    with tarfile.open(sdist, mode="w:gz") as archive:
        for suffix in distribution.SDIST_REQUIRED:
            content = b"safe"
            regular = tarfile.TarInfo(f"eigendark_agent_mcp-{VERSION}/{suffix}")
            regular.size = len(content)
            archive.addfile(regular, io.BytesIO(content))
        member = tarfile.TarInfo(f"eigendark_agent_mcp-{VERSION}/unsafe-link")
        member.type = tarfile.SYMTYPE
        member.linkname = "../../escape"
        archive.addfile(member)
    with pytest.raises(ValueError, match="links or special files"):
        distribution.check_sdist(sdist)
