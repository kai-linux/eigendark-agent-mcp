from __future__ import annotations

import urllib.parse
from collections import UserDict

import pytest

from eigendark_agent_mcp.errors import ToolError
from eigendark_agent_mcp.runtime import CredentialStore
from eigendark_agent_mcp.security import (
    REDACTED,
    UNTRUSTED_DATA_NOTICE,
    ensure_no_secret,
    is_secret_field,
    public_result,
    redact_text,
    sanitize_public,
)


def test_credential_store_lifecycle_and_environment_precedence(monkeypatch: pytest.MonkeyPatch):
    store = CredentialStore(max_matches=2)
    store.remember_api_key("api_runtime_credential")
    store.remember_ticket("mmt_runtime_ticket")
    store.remember_match("M1", 0, "seat_runtime_one", "spectator_runtime_one")

    assert store.require_api_key() == "api_runtime_credential"
    assert store.require_ticket() == "mmt_runtime_ticket"
    assert store.seat_token("M1", 0) == "seat_runtime_one"
    assert store.spectator_token("M1", 0) == "spectator_runtime_one"

    monkeypatch.setenv("EIGENDARK_API_KEY", "api_environment_credential")
    monkeypatch.setenv("ED_API_KEY", "api_alias_environment_credential")
    monkeypatch.setenv("EIGENDARK_SEAT_TOKEN", "seat_environment_credential")
    monkeypatch.setenv("ED_SEAT_TOKEN", "seat_alias_environment_credential")
    assert store.require_api_key() == "api_environment_credential"
    assert store.seat_token("unknown", 1) == "seat_environment_credential"
    assert set(store.sensitive_values()) >= {
        "api_environment_credential",
        "api_alias_environment_credential",
        "api_runtime_credential",
        "seat_environment_credential",
        "seat_alias_environment_credential",
        "seat_runtime_one",
    }

    store.clear_ticket()
    with pytest.raises(ToolError, match="ticket"):
        store.require_ticket()
    store.reset()
    assert store.ticket() is None


def test_credential_store_is_bounded_and_lru():
    store = CredentialStore(max_matches=2)
    store.remember_match("M1", 0, "seat_credential_one")
    store.remember_match("M2", 0, "seat_credential_two")
    assert store.seat_token("M1", 0) == "seat_credential_one"  # refresh M1
    store.remember_match("M3", 0, "seat_credential_three")
    with pytest.raises(ToolError, match="No seat credential"):
        store.seat_token("M2", 0)
    assert store.spectator_token("M3", 0) == "seat_credential_three"


def test_environment_credentials_are_validated(monkeypatch: pytest.MonkeyPatch):
    store = CredentialStore()
    monkeypatch.setenv("EIGENDARK_API_KEY", "invalid\nheader")
    with pytest.raises(ToolError, match="invalid API key"):
        store.require_api_key()
    monkeypatch.delenv("EIGENDARK_API_KEY")
    monkeypatch.setenv("EIGENDARK_SEAT_TOKEN", "invalid seat with spaces")
    with pytest.raises(ToolError, match="invalid seat token"):
        store.seat_token("M", 0)


@pytest.mark.parametrize(
    ("method", "arguments"),
    [
        ("remember_api_key", ("",)),
        ("remember_ticket", (42,)),
        ("remember_match", ("", 0, "seat_valid_value")),
        ("remember_match", ("M", True, "seat_valid_value")),
        ("remember_match", ("M", 2, "seat_valid_value")),
        ("remember_match", ("M", 0, "")),
        ("remember_match", ("M", 0, "seat_invalid\nvalue")),
        ("remember_match", ("M\ninvalid", 0, "seat_valid_value")),
    ],
)
def test_credential_store_rejects_invalid_values(method: str, arguments: tuple[object, ...]):
    store = CredentialStore()
    with pytest.raises(ToolError):
        getattr(store, method)(*arguments)
    with pytest.raises(ValueError, match="positive"):
        CredentialStore(max_matches=0)


@pytest.mark.parametrize(
    "field",
    [
        "token",
        "seatToken",
        "CLIENT_SECRET",
        "user-password",
        "some_refresh_token",
        "Authorization",
        "private_key",
    ],
)
def test_secret_field_detection(field: str):
    assert is_secret_field(field)
    assert not is_secret_field("token_count")
    assert not is_secret_field("public_key_prefix")


def test_recursive_sanitization_redacts_fields_values_and_controls(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("EIGENDARK_API_KEY", "api_known_environment_secret")
    encoded = urllib.parse.quote("api_known_environment_secret", safe="")
    payload = UserDict(
        {
            "token": "not-visible",
            "nested": {
                "safe": f"prefix api_known_environment_secret {encoded}",
                "message": "Bearer abcdefghijklmnop\x00",
            },
            "items": [{"clientSecret": "also-hidden"}],
            "finite": 1.5,
            "infinite": float("inf"),
            "other": object(),
        }
    )
    result = sanitize_public(payload)
    assert result["token"] == REDACTED
    assert "api_known_environment_secret" not in result["nested"]["safe"]
    assert result["nested"]["message"] == f"Bearer {REDACTED}�"
    assert result["items"][0]["clientSecret"] == REDACTED
    assert result["finite"] == 1.5
    assert result["infinite"] is None
    assert result["other"] == "[unsupported value]"


def test_redact_text_catches_credential_patterns_and_extra_values():
    text = "Bearer abcdefghij ed_abcdefghijk mmt_abcdefghijk custom-sensitive"
    rendered = redact_text(text, extra_sensitive=("custom-sensitive",))
    assert "abcdefghij" not in rendered
    assert "custom-sensitive" not in rendered
    assert rendered.count(REDACTED) >= 4


def test_sanitization_enforces_structural_bounds():
    with pytest.raises(ToolError, match="oversized array"):
        sanitize_public(list(range(2_001)))
    with pytest.raises(ToolError, match="oversized object"):
        sanitize_public({str(index): index for index in range(513)})
    deeply_nested: object = "leaf"
    for _ in range(18):
        deeply_nested = [deeply_nested]
    with pytest.raises(ToolError, match="nested too deeply"):
        sanitize_public(deeply_nested)
    assert len(sanitize_public("x" * 10_000)) == 8_192


def test_outbound_dlp_rejects_known_encoded_and_obvious_secrets(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("EIGENDARK_API_KEY", "api_known_environment_secret")
    for value in (
        "api_known_environment_secret",
        urllib.parse.quote_plus("api_known_environment_secret"),
        "Bearer abcdefghijklmnop",
        {"nested": ["mmt_credentialvalue"]},
    ):
        with pytest.raises(ToolError, match="Refusing"):
            ensure_no_secret(value, "public field")
    ensure_no_secret({"card_id": "Eigendark_5"}, "action")


def test_public_result_adds_notice_and_sanitizes():
    result = public_result({"apiKey": "ed_" + "secretcredential", "safe": "yes"})
    assert result == {
        "apiKey": REDACTED,
        "safe": "yes",
        "security_notice": UNTRUSTED_DATA_NOTICE,
    }
