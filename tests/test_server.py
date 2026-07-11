from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import anyio
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client

from eigendark_agent_mcp import __version__, server
from eigendark_agent_mcp.errors import ToolError

ROOT = Path(__file__).resolve().parents[1]


def test_official_mcp_client_conformance_and_safe_validation():
    async def scenario() -> None:
        with tempfile.TemporaryFile(mode="w+") as errlog:
            parameters = StdioServerParameters(
                command=sys.executable,
                args=["-m", "eigendark_agent_mcp.server"],
                cwd=ROOT,
                env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
            )
            async with (
                stdio_client(parameters, errlog=errlog) as (read_stream, write_stream),
                ClientSession(read_stream, write_stream) as session,
            ):
                initialized = await session.initialize()
                assert initialized.serverInfo.name == "eigendark-agent-mcp"
                assert initialized.serverInfo.version == __version__
                listed = await session.list_tools()
                assert len(listed.tools) == 11
                for tool in listed.tools:
                    assert "api_key" not in tool.inputSchema.get("properties", {})
                    assert "token" not in tool.inputSchema.get("properties", {})
                guide = await session.call_tool("agent_protocol_guide", {})
                assert guide.isError is False
                assert guide.structuredContent["security_notice"]
                secret = "credential_from_model"
                invalid = await session.call_tool(
                    "submit_action",
                    {
                        "match_id": "M",
                        "seat": 0,
                        "kind": secret,
                        "args": {},
                    },
                )
                assert invalid.isError is True
                assert secret not in invalid.content[0].text
            errlog.seek(0)
            assert errlog.read() == ""

    anyio.run(scenario)


def test_stdio_is_newline_json_not_content_length():
    initialize = (
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":'
        '{"protocolVersion":"2025-11-25","capabilities":{},'
        '"clientInfo":{"name":"test","version":"1"}}}\n'
    )
    process = subprocess.run(
        [sys.executable, "-m", "eigendark_agent_mcp.server"],
        input=initialize,
        text=True,
        capture_output=True,
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        timeout=10,
        check=True,
    )
    assert "Content-Length" not in process.stdout
    assert '"name":"eigendark-agent-mcp"' in process.stdout
    assert process.stderr == ""


def test_error_result_redacts_secret_patterns():
    result = server._error_result("failed Bearer abcdefghijklmnop")
    assert result.isError is True
    assert "abcdefghijklmnop" not in result.content[0].text


def test_direct_server_handlers_cover_success_and_safe_failures(monkeypatch):
    async def scenario() -> None:
        listed = await server.list_tools()
        assert len(listed) == 11
        guide = await server.call_tool("agent_protocol_guide", {})
        assert guide["security_notice"]
        invalid = await server.call_tool("submit_action", {"match_id": "M"})
        assert invalid.isError is True
        not_mapping = await server.call_tool("agent_protocol_guide", [])
        assert not_mapping.isError is True

        monkeypatch.setattr(
            server, "invoke_tool", lambda *args: (_ for _ in ()).throw(RuntimeError("private"))
        )
        internal = await server.call_tool("agent_protocol_guide", {})
        assert internal.isError is True
        assert "private" not in internal.content[0].text

        monkeypatch.setattr(
            server, "invoke_tool", lambda *args: (_ for _ in ()).throw(ToolError("safe error"))
        )
        expected = await server.call_tool("agent_protocol_guide", {})
        assert expected.isError is True
        assert "safe error" in expected.content[0].text

    anyio.run(scenario)


class FakeTextStream:
    def __init__(self, content: bytes = b""):
        self.buffer = io.BytesIO(content)


def test_bounded_transport_reads_and_writes_newline_json(monkeypatch):
    request = b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}\n'
    fake_stdin = FakeTextStream(request)
    fake_stdout = FakeTextStream()
    monkeypatch.setattr(server.sys, "stdin", fake_stdin)
    monkeypatch.setattr(server.sys, "stdout", fake_stdout)

    async def scenario() -> None:
        async with server.bounded_stdio_server() as (read_stream, write_stream):
            incoming = await read_stream.receive()
            assert incoming.message.root.method == "tools/list"
            await write_stream.send(
                server.SessionMessage(
                    types.JSONRPCMessage(
                        root=types.JSONRPCResponse(jsonrpc="2.0", id=1, result={"ok": True})
                    )
                )
            )
            await write_stream.aclose()

    anyio.run(scenario)
    assert fake_stdout.buffer.getvalue() == b'{"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n'


def test_bounded_reader_drains_oversized_line_and_handles_eof(monkeypatch):
    monkeypatch.setattr(server, "MAX_STDIO_MESSAGE_BYTES", 8)
    fake_stdin = FakeTextStream(b"0123456789abcdef\nnext\n")
    monkeypatch.setattr(server.sys, "stdin", fake_stdin)
    assert server._read_stdin_line() is server.OVERSIZED_MESSAGE
    assert server._read_stdin_line() == b"next\n"
    assert server._read_stdin_line() is None


def test_bounded_output_replaces_oversized_response(monkeypatch):
    response = types.JSONRPCMessage(
        root=types.JSONRPCResponse(jsonrpc="2.0", id=7, result={"value": "x" * 200})
    )
    monkeypatch.setattr(server, "MAX_STDIO_MESSAGE_BYTES", 100)
    payload = server._bounded_output(server.SessionMessage(response))
    assert b"Response exceeded the safe size limit" in payload
    assert b'"id":7' in payload

    notification = types.JSONRPCMessage(
        root=types.JSONRPCNotification(
            jsonrpc="2.0", method="notifications/test", params={"value": "x" * 200}
        )
    )
    assert server._bounded_output(server.SessionMessage(notification)) == b""


def test_main_has_sanitized_exit_paths(monkeypatch):
    monkeypatch.setattr(server.anyio, "run", lambda function: None)
    assert server.main() == 0

    monkeypatch.setattr(
        server.anyio, "run", lambda function: (_ for _ in ()).throw(KeyboardInterrupt())
    )
    assert server.main() == 0

    stderr = io.StringIO()
    monkeypatch.setattr(server.sys, "stderr", stderr)
    monkeypatch.setattr(
        server.anyio, "run", lambda function: (_ for _ in ()).throw(RuntimeError("secret detail"))
    )
    assert server.main() == 1
    assert "secret detail" not in stderr.getvalue()
