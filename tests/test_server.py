import io
import json
import os
import subprocess
from pathlib import Path
import sys
import urllib.error

import pytest

from eigendark_agent_mcp import server as mcp


def test_initialize_response_advertises_tools():
    response = mcp.handle_request({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0"},
        },
    })

    assert response["result"]["serverInfo"]["name"] == "eigendark-agent-mcp"
    assert response["result"]["capabilities"]["tools"]["listChanged"] is False


def test_tools_list_exposes_player_and_onboarding_surface(monkeypatch):
    response = mcp.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})

    tools = {tool["name"]: tool for tool in response["result"]["tools"]}
    assert {
        "agent_protocol_guide",
        "get_match_state",
        "submit_action",
        "summarize_state",
        "onboard_sandbox",
        "create_bot_match",
        "share_replay",
    }.issubset(tools)
    # api_key appears ONLY where it is the point (match creation); the play
    # loop stays seat-token based.
    for name, tool in tools.items():
        props = tool["inputSchema"].get("properties", {})
        if name == "create_bot_match":
            assert "api_key" in props
        else:
            assert "api_key" not in props


def test_pow_solver_roundtrip():
    challenge_id = "a" * 32
    nonce = mcp.solve_pow(challenge_id, 2)
    import hashlib
    digest = hashlib.sha256(f"{challenge_id}:{nonce}".encode()).hexdigest()
    assert digest.startswith("00")
    assert mcp.solve_zone(8, 2) == 6


def test_credential_tools_skip_result_redaction():
    # onboard_sandbox / create_bot_match must return usable credentials;
    # everything else stays redacted.
    plain = mcp._content_result({"api_key": "ed_secret"}, redact=False)
    assert plain["structuredContent"]["api_key"] == "ed_secret"
    redacted = mcp._content_result({"api_key": "ed_secret"})
    assert redacted["structuredContent"]["api_key"] == "[redacted]"
    assert mcp.BASE_TOOLS["onboard_sandbox"].get("returns_credentials") is True
    assert mcp.BASE_TOOLS["create_bot_match"].get("returns_credentials") is True
    assert not mcp.BASE_TOOLS["get_match_state"].get("returns_credentials")


def test_secret_fields_are_redacted_recursively():
    payload = {
        "token": "seat-secret",
        "nested": {"api_key": "credential-secret", "safe": "visible"},
        "items": [{"Authorization": "Bearer hidden"}],
    }

    assert mcp._redact(payload) == {
        "token": "[redacted]",
        "nested": {"api_key": "[redacted]", "safe": "visible"},
        "items": [{"Authorization": "[redacted]"}],
    }


def test_untrusted_base_url_is_rejected_by_default(monkeypatch):
    monkeypatch.setenv("EIGENDARK_BASE_URL", "https://example.invalid")
    monkeypatch.delenv("EIGENDARK_MCP_ALLOW_UNTRUSTED_BASE_URL", raising=False)

    with pytest.raises(mcp.ToolError, match="Refusing to send tokens"):
        mcp._base_url_or_error()


def test_localhost_base_url_is_allowed(monkeypatch):
    monkeypatch.setenv("EIGENDARK_BASE_URL", "http://localhost:5000")

    assert mcp._base_url_or_error() == "http://localhost:5000"


@pytest.mark.parametrize(
    "url",
    [
        "http://www.eigendark.com",
        "https://www.eigendark.com:8443",
        "https://user@www.eigendark.com",
        "https://www.eigendark.com:not-a-port",
        "https://www.eigendark.com?token=leak",
        "https://www.eigendark.com#fragment",
    ],
)
def test_production_base_url_rejects_unsafe_variants(monkeypatch, url):
    monkeypatch.setenv("EIGENDARK_BASE_URL", url)
    monkeypatch.delenv("EIGENDARK_MCP_ALLOW_UNTRUSTED_BASE_URL", raising=False)

    with pytest.raises(mcp.ToolError, match="Refusing to send tokens"):
        mcp._base_url_or_error()


def test_production_base_url_requires_https_default_port(monkeypatch):
    monkeypatch.setenv("EIGENDARK_BASE_URL", "https://www.eigendark.com:443")

    assert mcp._base_url_or_error() == "https://www.eigendark.com:443"


def test_create_match_is_not_a_public_tool():
    response = mcp.handle_request({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "create_agent_match",
            "arguments": {"deck_a": "A", "deck_b": "B"},
        },
    })

    assert response["error"]["code"] == -32602
    assert "unknown tool" in response["error"]["message"]


def test_api_key_argument_is_rejected_even_when_tool_called_directly():
    with pytest.raises(mcp.ToolError, match="unexpected argument"):
        mcp.tool_get_match_state({
            "match_id": "M",
            "seat": 0,
            "token": "seat-token",
            "api_key": "credential_from_model",
        })


def test_content_result_redacts_structured_output():
    result = mcp._content_result({"tokens": ["a", "b"], "token": "c"})

    assert json.loads(result["content"][0]["text"]) == {
        "token": "[redacted]",
        "tokens": ["a", "b"],
    }
    assert result["structuredContent"]["token"] == "[redacted]"


def test_http_errors_redact_env_and_request_secret_values(monkeypatch):
    monkeypatch.setenv("EIGENDARK_BASE_URL", "https://www.eigendark.com")

    def fake_urlopen(request, timeout):
        body = b'{"message": "failed for seat-token"}'
        raise urllib.error.HTTPError(request.full_url, 403, "Forbidden", {}, io.BytesIO(body))

    monkeypatch.setattr(mcp.urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(mcp.ToolError) as exc:
        mcp._json_request(
            "GET",
            "/api/test",
            query={"token": "seat-token"},
        )

    message = str(exc.value)
    assert "seat-token" not in message
    assert "[redacted]" in message


def test_stdio_framed_initialize_smoke():
    message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "smoke", "version": "0"},
        },
    }
    raw = json.dumps(message).encode("utf-8")
    env = dict(os.environ)
    # Run from the checkout even when the package isn't installed into the
    # test interpreter.
    src_dir = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = src_dir + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.Popen(
        [sys.executable, "-m", "eigendark_agent_mcp.server"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    assert proc.stdin is not None
    assert proc.stdout is not None
    proc.stdin.write(f"Content-Length: {len(raw)}\r\n\r\n".encode("ascii") + raw)
    proc.stdin.close()

    header = proc.stdout.readline().decode("ascii")
    proc.stdout.readline()
    length = int(header.split(":", 1)[1].strip())
    body = proc.stdout.read(length)
    stderr = proc.stderr.read().decode("utf-8") if proc.stderr else ""
    proc.wait(timeout=5)

    assert stderr == ""
    assert json.loads(body)["result"]["serverInfo"]["name"] == "eigendark-agent-mcp"
