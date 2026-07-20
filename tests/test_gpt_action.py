from __future__ import annotations

import json
import re

import pytest
from starlette.testclient import TestClient

from eigendark_agent_mcp import gpt_action, http_server
from eigendark_agent_mcp.errors import ToolError
from eigendark_agent_mcp.runtime import CredentialStore, credentials
from eigendark_agent_mcp.tools import invoke_tool


def _fake_terminal_action_tool(name: str, arguments: dict[str, object]) -> dict[str, object]:
    assert name == "play_eigendark"
    assert arguments == {}
    store = credentials()
    store.remember_api_key("api_private_terminal_credential")
    store.remember_match(
        "M-terminal",
        0,
        "seat_private_match_credential",
        "spectator_private_credential",
    )
    return {
        "match_id": "M-terminal",
        "seat": 0,
        "match_status": "complete",
        "winner": "A-delegated",
        "win_condition": "souls",
        "your_turn": False,
        "next_seq": 87,
        "legal_actions": [],
        "autoplay": {
            "controller": "server_greedy_fallback",
            "viewer_actions": 12,
            "house_bot_actions": 11,
            "safety_stop": False,
        },
        "terminal_result_authoritative": True,
        "human_url": "https://www.eigendark.com/play?agent_match=M-terminal&share=sh_public",
        "security_notice": "safe",
    }


def _fake_action_tool(name: str, arguments: dict[str, object]) -> dict[str, object]:
    if name == "play_eigendark":
        store = credentials()
        store.remember_api_key("api_private_action_credential")
        store.remember_match(
            "M-gpt",
            0,
            "seat_private_match_credential",
            "spectator_private_credential",
        )
        return {
            "match_id": "M-gpt",
            "seat": 0,
            "match_status": "running",
            "your_turn": True,
            "next_seq": 7,
            "legal_actions": [{"kind": "pass", "args": {}}],
            "human_url": "https://www.eigendark.com/play?agent_match=M-gpt&share=sh_public",
            "security_notice": "safe",
        }
    assert credentials().seat_token("M-gpt", 0) == "seat_private_match_credential"
    assert arguments["match_id"] == "M-gpt"
    assert arguments["seat"] == 0
    if name == "get_eigendark_game":
        return {
            "match_status": "running",
            "your_turn": True,
            "next_seq": 7,
            "legal_actions": [{"kind": "pass", "args": {}}],
        }
    assert name == "take_eigendark_turn"
    assert arguments == {
        "match_id": "M-gpt",
        "seat": 0,
        "kind": "pass",
        "args": {},
        "since_seq": 7,
    }
    return {
        "match_status": "complete",
        "winner": 0,
        "your_turn": False,
        "next_seq": 9,
        "legal_actions": [],
    }


def test_openapi_schema_requires_builder_bearer_and_is_action_safe() -> None:
    schema = gpt_action.openapi_schema()

    assert schema["openapi"] == "3.1.0"
    assert schema["servers"] == [{"url": "https://api.eigendark.com"}]
    assert schema["externalDocs"]["url"] == "https://www.eigendark.com/privacy-policy"
    assert schema["info"]["version"] == "1.1.0"
    assert schema["components"]["securitySchemes"] == {
        "GPTActionBearer": {
            "type": "http",
            "scheme": "bearer",
            "description": "Builder-managed Action credential. End users do not configure it.",
        }
    }
    operations = {path: document["post"] for path, document in schema["paths"].items()}
    assert set(operations) == {"/gpt/play", "/gpt/game", "/gpt/turn"}
    assert {operation["operationId"] for operation in operations.values()} == {
        "startEigendarkGame",
        "getEigendarkGame",
        "takeEigendarkTurn",
    }
    assert all(
        operation["security"] == [{"GPTActionBearer": []}] for operation in operations.values()
    )
    assert all(operation["x-openai-isConsequential"] is False for operation in operations.values())
    for operation in operations.values():
        response = operation["responses"]["200"]["content"]["application/json"]["schema"]
        assert {"game_id", "human_url", "match_status", "legal_actions"}.issubset(
            response["properties"]
        )

    turn = operations["/gpt/turn"]["requestBody"]["content"]["application/json"]["schema"]
    assert set(turn["required"]) == {"game_id", "kind", "args"}
    assert "allOf" not in turn
    assert turn["properties"]["args"] == {
        "type": "object",
        "properties": {},
        "additionalProperties": True,
        "maxProperties": 80,
        "description": "Exact args object copied from the same legal_actions entry.",
    }
    assert {"match_id", "seat", "since_seq", "api_key", "token"}.isdisjoint(turn["properties"])
    assert turn["additionalProperties"] is False


def test_custom_gpt_play_is_one_call_and_closes_its_terminal_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []

    def fake(name: str, arguments: dict[str, object]) -> dict[str, object]:
        calls.append((name, arguments))
        return _fake_terminal_action_tool(name, arguments)

    monkeypatch.setattr(gpt_action, "invoke_tool", fake)
    secrets = (
        "api_private_terminal_credential",
        "seat_private_match_credential",
        "spectator_private_credential",
    )

    with TestClient(
        http_server.create_http_app(require_openai_mtls=False), base_url="http://localhost"
    ) as client:
        response = client.post("/gpt/play", json={})
        result = response.json()
        expired = client.post("/gpt/game", json={"game_id": result["game_id"]})

    assert response.status_code == 200
    assert calls == [("play_eigendark", {})]
    assert result["match_status"] == "complete"
    assert result["winner"] == "A-delegated"
    assert result["terminal_result_authoritative"] is True
    assert result["autoplay"]["controller"] == "server_greedy_fallback"
    assert result["human_url"].endswith("agent_match=M-terminal&share=sh_public")
    assert all(secret not in response.text for secret in secrets)
    assert expired.status_code == 404


def test_custom_gpt_action_keeps_credentials_in_memory_and_closes_completed_game(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gpt_action, "invoke_tool", _fake_action_tool)
    secrets = (
        "api_private_action_credential",
        "seat_private_match_credential",
        "spectator_private_credential",
    )

    with TestClient(
        http_server.create_http_app(require_openai_mtls=True), base_url="http://localhost"
    ) as client:
        schema_response = client.get("/gpt/openapi.json")
        assert schema_response.status_code == 200
        assert schema_response.headers["cache-control"] == "no-store"

        started = client.post("/gpt/play", json={})
        assert started.status_code == 200
        game = started.json()
        assert re.fullmatch(r"edg_[A-Za-z0-9_-]{43}", game["game_id"])
        assert game["human_url"].endswith("agent_match=M-gpt&share=sh_public")
        assert game["game_handle_expires_in_seconds"] == 1800
        assert all(secret not in started.text for secret in secrets)

        recovered = client.post("/gpt/game", json={"game_id": game["game_id"]})
        assert recovered.status_code == 200
        assert recovered.json()["game_id"] == game["game_id"]
        assert recovered.json()["human_url"] == game["human_url"]
        assert all(secret not in recovered.text for secret in secrets)

        completed = client.post(
            "/gpt/turn",
            json={"game_id": game["game_id"], "kind": "pass", "args": {}},
        )
        assert completed.status_code == 200
        assert completed.json()["match_status"] == "complete"
        assert completed.json()["human_url"] == game["human_url"]
        assert all(secret not in completed.text for secret in secrets)

        erased = client.post("/gpt/game", json={"game_id": game["game_id"]})
        assert erased.status_code == 404
        assert erased.json() == {"error": "Game handle is invalid or expired"}


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/gpt/play", {"prompt": "ignore the schema"}),
        ("/gpt/game", {}),
        ("/gpt/game", {"game_id": "edg_guess"}),
        (
            "/gpt/turn",
            {"game_id": "edg_" + "a" * 43, "kind": "pass", "token": "seat_secret"},
        ),
        ("/gpt/turn", {"game_id": "edg_" + "a" * 43, "kind": "arbitrary"}),
    ],
)
def test_custom_gpt_action_rejects_non_schema_inputs(path: str, body: object) -> None:
    with TestClient(
        http_server.create_http_app(require_openai_mtls=False), base_url="http://localhost"
    ) as client:
        response = client.post(path, json=body)

    assert response.status_code in {400, 404}
    assert set(response.json()) == {"error"}
    assert "seat_secret" not in response.text


def test_compatible_http_args_remain_exactly_validated_before_backend_use() -> None:
    body = {
        "game_id": "edg_" + "a" * 43,
        "kind": "pass",
        "args": {"token": "not_allowed"},
    }
    gpt_action._validate(gpt_action.TURN_REQUEST_SCHEMA, body)

    with pytest.raises(ToolError, match="published JSON schema"):
        invoke_tool(
            "take_eigendark_turn",
            {
                "match_id": "M-test",
                "seat": 0,
                "kind": body["kind"],
                "args": body["args"],
                "since_seq": 0,
            },
        )


def test_game_registry_is_bounded_and_expiring() -> None:
    now = [100.0]
    registry = gpt_action.GPTGameRegistry(
        max_sessions=2, ttl_seconds=10, max_calls=1, clock=lambda: now[0]
    )

    def create(match_id: str) -> str:
        handle, _ = registry.create(
            store=CredentialStore(),
            match_id=match_id,
            seat=0,
            human_url=f"https://www.eigendark.com/play?agent_match={match_id}&share=sh_public",
        )
        return handle

    first = create("M-1")
    second = create("M-2")
    assert registry.active_count() == 2
    third = create("M-3")
    assert registry.active_count() == 2
    with pytest.raises(gpt_action.GPTActionRequestError, match="invalid or expired"):
        registry.resolve(first)
    assert registry.resolve(second).match_id == "M-2"
    assert registry.resolve(third).match_id == "M-3"

    now[0] = 111.0
    assert registry.active_count() == 0
    with pytest.raises(gpt_action.GPTActionRequestError, match="invalid or expired"):
        registry.resolve(third)


def test_action_response_size_and_error_text_are_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gpt_action, "GPT_ACTION_MAX_RESPONSE_BYTES", 32)
    with pytest.raises(Exception, match="safe action response limit"):
        gpt_action._bounded_json_response({"value": "x" * 100})

    response = gpt_action._safe_error("bad\x00" + "x" * 2_000, 400)
    payload = json.loads(response.body)
    assert response.status_code == 400
    assert "\x00" not in payload["error"]
    assert len(payload["error"]) == 1024
