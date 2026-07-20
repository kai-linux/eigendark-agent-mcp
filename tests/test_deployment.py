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


def test_systemd_runtime_cannot_read_home_credentials() -> None:
    unit = (ROOT / "deploy/eigendark-agent-mcp.service").read_text(encoding="utf-8")
    installer = (ROOT / "deploy/install-production.sh").read_text(encoding="utf-8")

    assert "ProtectHome=true" in unit
    assert "WorkingDirectory=/\n" in unit
    assert "WorkingDirectory=/home" not in unit
    assert "BindReadOnlyPaths=" not in unit
    assert "ExecStart=/opt/eigendark-agent-mcp/.venv/bin/python -m " in unit
    assert ".venv/bin/eigendark-agent-mcp-http" not in unit
    assert "RUNTIME=/opt/eigendark-agent-mcp" in installer
    assert "PYTHON_INSTALL_ROOT=/opt/eigendark-python" in installer
    assert "systemctl start eigendark-agent-mcp.service" in installer
    assert "RUNTIME_PREVIOUS" in installer


def test_custom_gpt_action_uses_validated_openai_egress_allowlist() -> None:
    nginx = (ROOT / "deploy/api.eigendark.nginx.conf").read_text(encoding="utf-8")
    installer = (ROOT / "deploy/install-production.sh").read_text(encoding="utf-8")

    assert "https://openai.com/chatgpt-actions.json" in installer
    assert "ipaddress.ip_network(value, strict=True)" in installer
    assert "network.is_global" in installer
    assert "OPENAI_ACTIONS_IP_DIR=/etc/nginx/openai-actions" in installer
    assert "include /etc/nginx/openai-actions/client-ips.conf;" in nginx
    assert nginx.count("if ($eigendark_openai_action_client = 0) { return 403; }") == 2
    assert "location = /gpt/openapi.json" in nginx
    assert "location = /gpt/play" in nginx
    assert "location ~ ^/gpt/(game|turn)$" in nginx
    assert "EIGENDARK_GPT_ACTION_REQUIRE_AUTH=1" in (
        ROOT / "deploy/eigendark-agent-mcp.service"
    ).read_text(encoding="utf-8")
    assert "EnvironmentFile=/etc/eigendark-agent-mcp/gpt-action.env" in (
        ROOT / "deploy/eigendark-agent-mcp.service"
    ).read_text(encoding="utf-8")
    assert "secrets.token_hex(32)" in installer
    assert "install -m 0600 -o root -g root" in installer
