from __future__ import annotations

import json
import urllib.parse
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from starlette.testclient import TestClient

from eigendark_agent_mcp import http_server
from eigendark_agent_mcp.errors import ToolError


def _client_certificate(*, dns_name: str = http_server.OPENAI_MTLS_DNS_NAME) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns_name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=5))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns_name)]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _initialize(client: TestClient) -> dict[str, str]:
    headers = {"Accept": "application/json, text/event-stream"}
    response = client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "security-test", "version": "1"},
            },
        },
    )
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["result"]["serverInfo"]["name"] == http_server.HTTP_SERVER_NAME
    return {**headers, "mcp-session-id": response.headers["mcp-session-id"]}


def test_streamable_http_lists_only_public_noauth_tools() -> None:
    with TestClient(
        http_server.create_http_app(require_openai_mtls=False), base_url="http://localhost"
    ) as client:
        headers = _initialize(client)
        response = client.post(
            "/mcp",
            headers=headers,
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )

    assert response.status_code == 200
    tools = response.json()["result"]["tools"]
    assert [tool["name"] for tool in tools] == [
        "play_eigendark",
        "get_eigendark_game",
        "take_eigendark_turn",
    ]
    for tool in tools:
        assert tool["securitySchemes"] == [{"type": "noauth"}]
        assert tool["_meta"]["securitySchemes"] == [{"type": "noauth"}]
        assert "api_key" not in tool["inputSchema"]["properties"]
        assert "token" not in tool["inputSchema"]["properties"]


def test_streamable_http_calls_with_session_context_and_sanitizes_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        http_server,
        "invoke_tool",
        lambda name, arguments: {"security_notice": "safe", "name": name},
    )
    with TestClient(
        http_server.create_http_app(require_openai_mtls=False), base_url="http://localhost"
    ) as client:
        headers = _initialize(client)
        response = client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "play_eigendark", "arguments": {}},
            },
        )
        assert response.json()["result"]["structuredContent"]["name"] == "play_eigendark"

        monkeypatch.setattr(
            http_server,
            "invoke_tool",
            lambda *args: (_ for _ in ()).throw(ToolError("safe public failure")),
        )
        failed = client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "play_eigendark", "arguments": {}},
            },
        )
        payload = json.loads(failed.json()["result"]["content"][0]["text"])
        assert payload == {"error": "safe public failure"}

        monkeypatch.setattr(
            http_server,
            "invoke_tool",
            lambda *args: (_ for _ in ()).throw(RuntimeError("private internal detail")),
        )
        internal = client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "play_eigendark", "arguments": {}},
            },
        )
        text = internal.json()["result"]["content"][0]["text"]
        assert "private internal detail" not in text


def test_mtls_gate_requires_verified_expected_client_certificate() -> None:
    app = http_server.create_http_app(require_openai_mtls=True)
    with TestClient(app, base_url="http://localhost") as client:
        denied = client.post("/mcp", json={})
        assert denied.status_code == 403
        wrong = client.post(
            "/mcp",
            headers={
                "x-openai-client-cert-verified": "SUCCESS",
                "x-openai-client-cert": urllib.parse.quote(
                    _client_certificate(dns_name="attacker.example"), safe=""
                ),
            },
            json={},
        )
        assert wrong.status_code == 403
        accepted_by_gate = client.post(
            "/mcp",
            headers={
                "x-openai-client-cert-verified": "SUCCESS",
                "x-openai-client-cert": urllib.parse.quote(_client_certificate(), safe=""),
            },
            json={},
        )
        assert accepted_by_gate.status_code != 403
        assert client.get("/healthz").json() == {"status": "ok"}


def test_invalid_certificates_body_limit_and_shared_credentials_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert http_server._valid_openai_cert("") is False
    assert http_server._valid_openai_cert("not-a-certificate") is False
    assert http_server._valid_openai_cert("x" * 16_385) is False

    monkeypatch.setattr(http_server, "MAX_HTTP_BODY_BYTES", 8)
    with TestClient(
        http_server.create_http_app(require_openai_mtls=False), base_url="http://localhost"
    ) as client:
        too_large = client.post("/mcp", content=b"0123456789")
    assert too_large.status_code == 413

    monkeypatch.setenv("EIGENDARK_API_KEY", "api_process_wide_secret")
    with pytest.raises(RuntimeError, match="refuses process-wide"):
        http_server._reject_shared_credentials()


def test_http_main_uses_loopback_and_has_sanitized_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    monkeypatch.setattr(http_server.uvicorn, "run", lambda app, **kwargs: calls.append(kwargs))
    monkeypatch.setenv("EIGENDARK_MCP_HTTP_PORT", "6003")
    assert http_server.main() == 0
    assert calls[0]["host"] == "127.0.0.1"
    assert calls[0]["port"] == 6003

    monkeypatch.setenv("EIGENDARK_MCP_HTTP_PORT", "invalid")
    assert http_server.main() == 1
