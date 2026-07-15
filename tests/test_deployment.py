from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_production_install_bootstraps_locked_build_backend_before_local_package() -> None:
    script = (ROOT / "deploy/install-production.sh").read_text(encoding="utf-8")
    runtime_lock = script.index("--require-hashes -r requirements-runtime.lock")
    build_lock = script.index("--require-hashes -r requirements-build.lock")
    local_package = script.index("--no-deps --no-build-isolation .")

    assert runtime_lock < build_lock < local_package
    assert script.count("--require-hashes") == 2
