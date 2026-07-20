from __future__ import annotations

import pytest

from eigendark_agent_mcp import tools
from eigendark_agent_mcp.runtime import CREDENTIALS


@pytest.fixture(autouse=True)
def isolated_credentials_and_environment(monkeypatch: pytest.MonkeyPatch):
    CREDENTIALS.reset()
    tools._clear_shared_sandbox_key()
    for name in (
        "EIGENDARK_API_KEY",
        "ED_API_KEY",
        "EIGENDARK_SEAT_TOKEN",
        "ED_SEAT_TOKEN",
        "EIGENDARK_BASE_URL",
        "ED_BASE_URL",
        "EIGENDARK_TIMEOUT_SECONDS",
        "ED_TIMEOUT_SECONDS",
        "EIGENDARK_MCP_ALLOW_UNTRUSTED_BASE_URL",
        "EIGENDARK_MCP_HTTP_PORT",
        "EIGENDARK_MCP_REQUIRE_OPENAI_MTLS",
    ):
        monkeypatch.delenv(name, raising=False)
    yield
    CREDENTIALS.reset()
    tools._clear_shared_sandbox_key()
