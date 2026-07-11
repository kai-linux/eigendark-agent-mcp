#!/usr/bin/env python3
"""Official-SDK MCP server with a bounded newline-delimited stdio transport."""

from __future__ import annotations

import json
import sys
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from typing import Any

import anyio
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from mcp import types
from mcp.server import NotificationOptions, Server
from mcp.server.lowlevel.server import InitializationOptions
from mcp.shared.message import SessionMessage

from . import __version__
from .errors import ToolError
from .security import UNTRUSTED_DATA_NOTICE, redact_text
from .tools import TOOL_DEFINITIONS, invoke_tool

SERVER_NAME = "eigendark-agent-mcp"
MAX_STDIO_MESSAGE_BYTES = 2 * 1024 * 1024
MAX_CONCURRENT_TOOL_CALLS = 8
SERVER_INSTRUCTIONS = (
    "Use only the seat-scoped Eigendark match tools. Credentials are resolved internally and "
    "must never be requested from or disclosed to a model. " + UNTRUSTED_DATA_NOTICE
)

MCP_SERVER = Server(SERVER_NAME, version=__version__, instructions=SERVER_INSTRUCTIONS)
TOOL_LIMITER = anyio.CapacityLimiter(MAX_CONCURRENT_TOOL_CALLS)


@MCP_SERVER.list_tools()
async def list_tools() -> list[types.Tool]:
    return [definition.as_mcp_tool() for definition in TOOL_DEFINITIONS]


@MCP_SERVER.call_tool(validate_input=False)
async def call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any] | types.CallToolResult:
    """Validate safely, then run blocking HTTP or proof-of-work away from the event loop."""

    if not isinstance(arguments, Mapping):
        return _error_result("Tool arguments must be an object")
    try:
        return await anyio.to_thread.run_sync(
            invoke_tool,
            name,
            dict(arguments),
            abandon_on_cancel=True,
            limiter=TOOL_LIMITER,
        )
    except ToolError as exc:
        return _error_result(str(exc))
    except Exception:
        return _error_result("The tool failed safely; no internal detail was returned")


def _error_result(message: str) -> types.CallToolResult:
    safe = redact_text(message)[:1_024]
    payload = {"error": safe}
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=json.dumps(payload, sort_keys=True))],
        structuredContent=None,
        isError=True,
    )


class _OversizedMessage:
    pass


OVERSIZED_MESSAGE = _OversizedMessage()


def _read_stdin_line() -> bytes | _OversizedMessage | None:
    raw = sys.stdin.buffer.readline(MAX_STDIO_MESSAGE_BYTES + 1)
    if raw == b"":
        return None
    oversized = len(raw) > MAX_STDIO_MESSAGE_BYTES
    while raw and not raw.endswith(b"\n"):
        raw = sys.stdin.buffer.readline(MAX_STDIO_MESSAGE_BYTES + 1)
        oversized = True
    return OVERSIZED_MESSAGE if oversized else raw


def _write_stdout_line(payload: bytes) -> None:
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.write(b"\n")
    sys.stdout.buffer.flush()


def _bounded_output(message: SessionMessage) -> bytes:
    payload = message.message.model_dump_json(by_alias=True, exclude_none=True).encode("utf-8")
    if len(payload) <= MAX_STDIO_MESSAGE_BYTES:
        return payload

    root = message.message.root
    request_id = getattr(root, "id", None)
    if type(request_id) not in {str, int}:
        # A server notification cannot be correlated with an error. Dropping an
        # impossible oversized notification is safer than emitting invalid JSON-RPC.
        return b""
    limited = types.JSONRPCMessage(
        root=types.JSONRPCError(
            jsonrpc="2.0",
            id=request_id,
            error=types.ErrorData(code=-32603, message="Response exceeded the safe size limit"),
        )
    )
    return limited.model_dump_json(by_alias=True, exclude_none=True).encode("utf-8")


@asynccontextmanager
async def bounded_stdio_server() -> AsyncIterator[
    tuple[
        MemoryObjectReceiveStream[SessionMessage | Exception],
        MemoryObjectSendStream[SessionMessage],
    ]
]:
    """Expose SDK streams while enforcing finite newline-framed messages."""

    read_send, read_receive = anyio.create_memory_object_stream[SessionMessage | Exception](0)
    write_send, write_receive = anyio.create_memory_object_stream[SessionMessage](0)

    async def stdin_reader() -> None:
        try:
            async with read_send:
                while True:
                    raw = await anyio.to_thread.run_sync(_read_stdin_line, abandon_on_cancel=True)
                    if raw is None:
                        return
                    if raw is OVERSIZED_MESSAGE:
                        await read_send.send(
                            ValueError("JSON-RPC message exceeded the safe size limit")
                        )
                        continue
                    try:
                        parsed = types.JSONRPCMessage.model_validate_json(raw)
                    except Exception:
                        await read_send.send(ValueError("Invalid JSON-RPC message"))
                        continue
                    await read_send.send(SessionMessage(parsed))
        except anyio.ClosedResourceError:  # pragma: no cover - shutdown race
            await anyio.lowlevel.checkpoint()

    async def stdout_writer() -> None:
        try:
            async with write_receive:
                async for session_message in write_receive:
                    payload = _bounded_output(session_message)
                    if payload:
                        await anyio.to_thread.run_sync(
                            _write_stdout_line, payload, abandon_on_cancel=True
                        )
        except anyio.ClosedResourceError:  # pragma: no cover - shutdown race
            await anyio.lowlevel.checkpoint()

    async with anyio.create_task_group() as task_group:
        task_group.start_soon(stdin_reader)
        task_group.start_soon(stdout_writer)
        yield read_receive, write_send


async def run_server() -> None:
    capabilities = MCP_SERVER.get_capabilities(
        NotificationOptions(prompts_changed=False, resources_changed=False, tools_changed=False),
        experimental_capabilities={},
    )
    initialization = InitializationOptions(
        server_name=SERVER_NAME,
        server_version=__version__,
        capabilities=capabilities,
        instructions=SERVER_INSTRUCTIONS,
        website_url="https://www.eigendark.com",
    )
    async with bounded_stdio_server() as (read_stream, write_stream):
        await MCP_SERVER.run(read_stream, write_stream, initialization, raise_exceptions=False)


def main() -> int:
    try:
        anyio.run(run_server)
    except KeyboardInterrupt:
        return 0
    except Exception:
        # Stderr is diagnostic transport; never serialize exception strings here.
        sys.stderr.write("eigendark-agent-mcp stopped after a safe internal failure\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
