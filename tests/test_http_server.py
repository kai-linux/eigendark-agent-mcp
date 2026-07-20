from __future__ import annotations

import json
import urllib.parse
from datetime import UTC, datetime, timedelta

import anyio
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


def test_public_endpoint_bypasses_mtls_and_serves_same_tools() -> None:
    # /mcp/public admits clients without the OpenAI connector certificate even
    # when the /mcp gate is enforced, and lists the identical public toolset.
    # In mtls (production) mode loopback hosts are dropped from the allowlist,
    # so connect with the production Host the way nginx forwards it.
    app = http_server.create_http_app(require_openai_mtls=True)
    with TestClient(app, base_url="http://api.eigendark.com") as client:
        headers = {"Accept": "application/json, text/event-stream"}
        response = client.post(
            "/mcp/public",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "connector-test", "version": "1"},
                },
            },
        )
        assert response.status_code == 200
        assert response.json()["result"]["serverInfo"]["name"] == "eigendark"
        session_headers = {**headers, "mcp-session-id": response.headers["mcp-session-id"]}
        listed = client.post(
            "/mcp/public",
            headers=session_headers,
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        assert listed.status_code == 200
        names = {tool["name"] for tool in listed.json()["result"]["tools"]}
        assert "play_eigendark" in names
        # The certificate gate on /mcp itself still holds.
        gated = client.post(
            "/mcp",
            headers=headers,
            json={"jsonrpc": "2.0", "id": 3, "method": "initialize", "params": {}},
        )
        assert gated.status_code == 403


def test_public_endpoint_caps_sessions_per_trusted_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(http_server, "MAX_PUBLIC_HTTP_SESSIONS_PER_CLIENT", 1)
    app = http_server.create_http_app(require_openai_mtls=False)
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "session-cap-test", "version": "1"},
        },
    }
    headers = {
        "Accept": "application/json, text/event-stream",
        "x-real-ip": "203.0.113.8",
    }
    with TestClient(app, base_url="http://localhost") as client:
        first = client.post("/mcp/public", headers=headers, json=request)
        second = client.post("/mcp/public", headers=headers, json=request)

    assert first.status_code == 200
    assert second.status_code == 503
    assert second.headers["retry-after"] == "30"
    assert second.json() == {"error": "Eigendark is at temporary session capacity"}


def test_session_admission_reserves_capacity_before_first_await(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = anyio.Event()
    release = anyio.Event()

    async def delayed_create(manager, scope, receive, send):
        started.set()
        await release.wait()
        manager._server_instances["created-session"] = object()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"mcp-session-id", b"created-session")],
            }
        )
        await send({"type": "http.response.body", "body": b"{}"})

    monkeypatch.setattr(
        http_server.StreamableHTTPSessionManager,
        "handle_request",
        delayed_create,
    )
    manager = http_server.BoundedSessionManager(
        app=object(),
        max_sessions=1,
        max_sessions_per_client=1,
    )
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/mcp/public",
        "headers": [(b"x-real-ip", b"203.0.113.8")],
        "client": ("127.0.0.1", 1234),
    }

    async def receive():
        return {"type": "http.disconnect"}

    first_messages = []
    second_messages = []

    async def send_first(message):
        first_messages.append(message)

    async def send_second(message):
        second_messages.append(message)

    async def scenario() -> None:
        async with anyio.create_task_group() as group:
            group.start_soon(manager.handle_request, scope, receive, send_first)
            await started.wait()
            await manager.handle_request(scope, receive, send_second)
            release.set()

    anyio.run(scenario)

    assert second_messages[0]["status"] == 503
    assert first_messages[0]["status"] == 200
    assert manager._pending_new_sessions == 0
    assert manager._session_clients == {"created-session": "203.0.113.8"}


def test_gpt_actions_require_constant_time_builder_bearer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "a" * 64
    monkeypatch.setenv("EIGENDARK_GPT_ACTION_KEY", secret)
    app = http_server.create_http_app(
        require_openai_mtls=False,
        require_gpt_action_auth=True,
    )
    with TestClient(app, base_url="http://localhost") as client:
        assert client.get("/gpt/openapi.json").status_code == 200
        missing = client.post("/gpt/play", json={})
        wrong = client.post(
            "/gpt/play",
            headers={"Authorization": f"Bearer {'b' * 64}"},
            json={},
        )
        authenticated = client.post(
            "/gpt/play",
            headers={"Authorization": f"bearer {secret}"},
            json={"unexpected": True},
        )

    assert missing.status_code == 401
    assert missing.headers["www-authenticate"] == "Bearer"
    assert wrong.status_code == 401
    assert secret not in missing.text + wrong.text
    assert authenticated.status_code == 400

    monkeypatch.delenv("EIGENDARK_GPT_ACTION_KEY")
    with pytest.raises(RuntimeError, match="no key is configured"):
        http_server.create_http_app(
            require_openai_mtls=False,
            require_gpt_action_auth=True,
        )


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

    monkeypatch.setattr(http_server, "MAX_GPT_ACTION_BODY_BYTES", 8)
    with TestClient(
        http_server.create_http_app(require_openai_mtls=False), base_url="http://localhost"
    ) as client:
        action_too_large = client.post("/gpt/play", content=b'{"value":"too large"}')
    assert action_too_large.status_code == 413

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
