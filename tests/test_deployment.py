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


def test_systemd_uses_moved_venv_safely_without_exposing_home_credentials() -> None:
    unit = (ROOT / "deploy/eigendark-agent-mcp.service").read_text(encoding="utf-8")
    installer = (ROOT / "deploy/install-production.sh").read_text(encoding="utf-8")

    assert "ProtectHome=tmpfs" in unit
    assert "BindReadOnlyPaths=/home/bitnami/eigendark-agent-mcp " in unit
    assert "/home/bitnami/eigendark/.runtime-python" in unit
    assert "/home/bitnami/eigendark/runtime\n" not in unit
    assert "ExecStart=/home/bitnami/eigendark-agent-mcp/.venv/bin/python -m " in unit
    assert ".venv/bin/eigendark-agent-mcp-http" not in unit
    assert "systemctl restart eigendark-agent-mcp.service" in installer
