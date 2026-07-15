from __future__ import annotations

import gc

import pytest

from eigendark_agent_mcp.errors import ToolError
from eigendark_agent_mcp.runtime import (
    CREDENTIALS,
    CredentialStore,
    SessionCredentialRegistry,
    credential_scope,
    credentials,
)


class Session:
    pass


def test_credential_scope_restores_default_and_isolates_stores() -> None:
    first = CredentialStore()
    second = CredentialStore()
    first.remember_api_key("api_first_session")
    second.remember_api_key("api_second_session")

    assert credentials() is CREDENTIALS
    with credential_scope(first):
        assert credentials().require_api_key() == "api_first_session"
        with credential_scope(second):
            assert credentials().require_api_key() == "api_second_session"
        assert credentials().require_api_key() == "api_first_session"
    assert credentials() is CREDENTIALS


def test_session_registry_reuses_only_same_live_session_and_releases_dead_one() -> None:
    registry = SessionCredentialRegistry()
    first_session = Session()
    second_session = Session()
    first = registry.for_session(first_session)
    assert registry.for_session(first_session) is first
    second = registry.for_session(second_session)
    assert second is not first
    first.remember_api_key("api_first_session")
    with pytest.raises(ToolError, match="No API key"):
        second.require_api_key()
    assert registry.active_count() == 2

    del first_session
    del first
    gc.collect()
    assert registry.active_count() == 1
