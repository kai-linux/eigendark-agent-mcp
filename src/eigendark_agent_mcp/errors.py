"""Errors safe to expose through the MCP tool boundary."""


class ToolError(RuntimeError):
    """A sanitized operational error that can be returned to an MCP client."""
