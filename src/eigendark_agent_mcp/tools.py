"""Eigendark MCP tool definitions and trusted handlers."""

from __future__ import annotations

import hashlib
import logging
import secrets
import threading
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from jsonschema import Draft202012Validator
from mcp import types

from .config import PRODUCTION_HOSTS, validated_base_url
from .errors import ToolError
from .http_client import json_request
from .runtime import credentials
from .security import (
    UNTRUSTED_DATA_NOTICE,
    ensure_no_secret,
    public_result,
    redact_text,
)

LOGGER = logging.getLogger(__name__)

MAX_POW_ITERATIONS = 5_000_000
IDENTIFIER_PATTERN = r"^[^\x00-\x1f\x7f]{1,256}$"
AGENT_ID_PATTERN = r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,47})$"
URL_SAFE_SHARE_QUERY_KEYS = frozenset({"agent_match", "share"})
URL_SAFE_SHARE_PATHS = frozenset({"/play", "/watch"})
_ONBOARD_LOCK = threading.Lock()

STRING_ID: dict[str, Any] = {
    "type": "string",
    "minLength": 1,
    "maxLength": 256,
    "pattern": IDENTIFIER_PATTERN,
}
SHORT_STRING: dict[str, Any] = {
    "type": "string",
    "minLength": 1,
    "maxLength": 128,
    "pattern": r"^[^\x00-\x1f\x7f]+$",
}
ID_ARRAY: dict[str, Any] = {
    "type": "array",
    "items": STRING_ID,
    "maxItems": 80,
    "uniqueItems": True,
}
ID_MAP: dict[str, Any] = {
    "type": "object",
    "propertyNames": STRING_ID,
    "additionalProperties": STRING_ID,
    "maxProperties": 80,
}
ALLOCATION_MAP: dict[str, Any] = {
    "type": "object",
    "propertyNames": STRING_ID,
    "additionalProperties": {"type": "integer", "minimum": 0, "maximum": 10_000},
    "maxProperties": 80,
}
EMPTY_ARGS: dict[str, Any] = {"type": "object", "properties": {}, "additionalProperties": False}


def _object_schema(
    properties: Mapping[str, Any],
    *,
    required: tuple[str, ...] = (),
    max_properties: int | None = None,
) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "object",
        "properties": dict(properties),
        "additionalProperties": False,
    }
    if required:
        schema["required"] = list(required)
    if max_properties is not None:
        schema["maxProperties"] = max_properties
    return schema


TARGET_PROPERTIES: dict[str, Any] = {
    "target": STRING_ID,
    "target_id": STRING_ID,
    "target_ids": ID_ARRAY,
    "allocations": ALLOCATION_MAP,
}

ACTION_ARGS_SCHEMAS: dict[str, dict[str, Any]] = {
    "play": _object_schema(
        {
            "card_id": STRING_ID,
            **TARGET_PROPERTIES,
            "host": STRING_ID,
            "host_id": STRING_ID,
            "target_player_idx": {"type": "integer", "enum": [0, 1]},
            "buffed_id": STRING_ID,
            "charged_id": STRING_ID,
            "capture_target_id": STRING_ID,
            "glitched_target_id": STRING_ID,
            "pounce_target_id": STRING_ID,
            "energize_mode": SHORT_STRING,
            "play_target_kind": SHORT_STRING,
            "devour_ids": ID_ARRAY,
        },
        required=("card_id",),
        max_properties=20,
    ),
    "pool": _object_schema({"card_id": STRING_ID}, required=("card_id",)),
    "activate_source": _object_schema({"card_id": STRING_ID}, required=("card_id",)),
    "attack": _object_schema(
        {
            "attackers": ID_ARRAY,
            "targets": ID_MAP,
            "overrides": ID_MAP,
            "auto_override": {"type": "boolean"},
        },
        required=("attackers",),
    ),
    "block": _object_schema(
        {
            "blockers": ID_MAP,
            "ambushes": ID_MAP,
            "auto_ambush": {"type": "boolean"},
            "attacker_id": STRING_ID,
            "blocker_id": STRING_ID,
        }
    ),
    "recall": _object_schema({"card_id": STRING_ID}, required=("card_id",)),
    "activate": _object_schema(
        {
            "card_id": STRING_ID,
            "mod_index": {"type": ["integer", "null"], "minimum": 0, "maximum": 255},
            "hand_skill": SHORT_STRING,
            **TARGET_PROPERTIES,
        },
        required=("card_id",),
    ),
    "attach": _object_schema(
        {"card_id": STRING_ID, "host_id": STRING_ID}, required=("card_id", "host_id")
    ),
    "ritual": _object_schema({"cards": ID_ARRAY, "ritual_id": STRING_ID}, required=("cards",)),
    "join_ritual": _object_schema(
        {"ritual_id": STRING_ID, "card_id": STRING_ID},
        required=("ritual_id", "card_id"),
    ),
    "resolve_ritual": _object_schema({"ritual_id": STRING_ID}, required=("ritual_id",)),
    "sustain_ritual": _object_schema({"ritual_id": STRING_ID}, required=("ritual_id",)),
    "choose_prompt_target": _object_schema(
        {
            "card_id": STRING_ID,
            "target_id": STRING_ID,
            "prompt_index": {"type": ["integer", "null"], "minimum": 0, "maximum": 255},
        },
        required=("card_id", "target_id"),
    ),
    "choose_prompt_distribution": _object_schema(
        {
            "card_id": STRING_ID,
            "prompt_index": {"type": ["integer", "null"], "minimum": 0, "maximum": 255},
            "target_ids": ID_ARRAY,
            "distribution_total": {"type": ["integer", "null"], "minimum": 0, "maximum": 10_000},
            "allocations": ALLOCATION_MAP,
        },
        required=("card_id", "allocations"),
    ),
    "draw": EMPTY_ARGS,
    "pass": _object_schema({"auto_ambush": {"type": "boolean"}}),
}

ACTION_KINDS = tuple(ACTION_ARGS_SCHEMAS)


def _action_input_schema() -> dict[str, Any]:
    common = {
        "match_id": STRING_ID,
        "seat": {"type": "integer", "enum": [0, 1]},
        "kind": {"type": "string", "enum": list(ACTION_KINDS)},
        "args": {"type": "object"},
        "since_seq": {"type": "integer", "minimum": 0, "maximum": 2_147_483_647},
        "pace_bot": {"type": "boolean"},
    }
    constraints = []
    for kind, args_schema in ACTION_ARGS_SCHEMAS.items():
        then: dict[str, Any] = {"properties": {"args": args_schema}}
        if kind not in {"draw", "pass"}:
            then["required"] = ["args"]
        constraints.append(
            {
                "if": {"properties": {"kind": {"const": kind}}, "required": ["kind"]},
                "then": then,
            }
        )
    return {
        "type": "object",
        "properties": common,
        "required": ["match_id", "seat", "kind"],
        "additionalProperties": False,
        "allOf": constraints,
    }


OUTPUT_BASE: dict[str, Any] = {
    "type": "object",
    "properties": {"security_notice": {"type": "string"}},
    "required": ["security_notice"],
    "additionalProperties": True,
}


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    name: str
    title: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[Mapping[str, Any]], dict[str, Any]]
    read_only: bool = False
    destructive: bool = False
    idempotent: bool = False
    open_world: bool = True

    def as_mcp_tool(self, *, noauth: bool = False) -> types.Tool:
        security_schemes = [{"type": "noauth"}] if noauth else None
        metadata: dict[str, Any] | None = None
        if security_schemes:
            metadata = {
                "securitySchemes": security_schemes,
                "openai/toolInvocation/invoking": f"Running {self.title.lower()}…"[:64],
                "openai/toolInvocation/invoked": f"Finished {self.title.lower()}."[:64],
            }
        return types.Tool(
            name=self.name,
            title=self.title,
            description=self.description,
            inputSchema=self.input_schema,
            outputSchema=OUTPUT_BASE,
            annotations=types.ToolAnnotations(
                title=self.title,
                readOnlyHint=self.read_only,
                destructiveHint=self.destructive,
                idempotentHint=self.idempotent,
                openWorldHint=self.open_world,
            ),
            securitySchemes=security_schemes,
            _meta=metadata,
        )


def solve_pow(challenge_id: str, difficulty: int) -> str:
    if not isinstance(challenge_id, str) or not (1 <= len(challenge_id) <= 128):
        raise ToolError("The onboarding challenge identifier was invalid")
    if type(difficulty) is not int or difficulty < 1 or difficulty > 6:
        raise ToolError("The onboarding proof-of-work difficulty was outside safe limits")
    target = "0" * difficulty
    for value in range(MAX_POW_ITERATIONS):
        nonce = str(value)
        digest = hashlib.sha256(f"{challenge_id}:{nonce}".encode()).hexdigest()
        if digest.startswith(target):
            return nonce
    raise ToolError(
        "The onboarding proof-of-work search limit was reached; request a new challenge"
    )


def solve_zone(zone_from: int, cost: int) -> int:
    if type(zone_from) is not int or type(cost) is not int:
        raise ToolError("The onboarding routing challenge was invalid")
    if not (-1_000_000 <= zone_from <= 1_000_000 and -1_000_000 <= cost <= 1_000_000):
        raise ToolError("The onboarding routing challenge was outside safe limits")
    return zone_from - cost


def tool_agent_protocol_guide(args: Mapping[str, Any]) -> dict[str, Any]:
    return public_result(
        {
            "mode": "player",
            "credential_handling": (
                "Credentials come only from environment configuration or trusted API responses, "
                "remain in bounded process memory, and are never tool arguments or results."
            ),
            "flow": [
                "Call onboard_sandbox once unless EIGENDARK_API_KEY is configured.",
                "Call create_bot_match, or join_matchmaking then matchmaking_status.",
                "Poll get_match_state until your_turn is true.",
                "Copy a kind/args pair from legal_actions into submit_action.",
                "Repeat until match_status is complete, then optionally call share_replay.",
            ],
            "actions": dict(ACTION_ARGS_SCHEMAS),
            "hidden_info": [
                "Opponent hand identities and deck order are redacted by the service.",
                "Each MCP process receives only its own seat capability.",
            ],
        }
    )


def tool_onboard_sandbox(args: Mapping[str, Any]) -> dict[str, Any]:
    if not _ONBOARD_LOCK.acquire(blocking=False):
        raise ToolError("Sandbox onboarding is already in progress")
    try:
        return _onboard_sandbox(args)
    finally:
        _ONBOARD_LOCK.release()


def _onboard_sandbox(args: Mapping[str, Any]) -> dict[str, Any]:
    name = args.get("name")
    if name is not None:
        ensure_no_secret(name, "name")
    challenge = json_request("POST", "/api/agent/onboard/challenge")
    challenge_id = _required_service_string(challenge, "challenge_id", max_length=128)
    protocol = _required_service_mapping(challenge, "reception_protocol")
    pow_spec = _required_service_mapping(challenge, "proof_of_work")
    algorithm = pow_spec.get("algorithm", "sha256")
    if algorithm != "sha256":
        raise ToolError("The onboarding service requested an unsupported proof-of-work algorithm")
    zone_to = solve_zone(protocol.get("zone_from"), protocol.get("cost"))
    nonce = solve_pow(challenge_id, pow_spec.get("difficulty"))
    body: dict[str, Any] = {
        "challenge_id": challenge_id,
        "zone_to": zone_to,
        "pow_nonce": nonce,
    }
    if isinstance(name, str):
        body["name"] = name
    minted = json_request("POST", "/api/agent/onboard", body=body)
    api_key = _required_service_string(minted, "api_key", max_length=4096)
    credentials().remember_api_key(api_key)
    limits = minted.get("limits") if isinstance(minted.get("limits"), Mapping) else {}
    safe_limits = {
        key: limits.get(key)
        for key in ("rate_per_min", "match_creates_per_day", "deck_saves_per_day")
        if _is_plain_number(limits.get(key))
    }
    return public_result(
        {
            "status": "ready",
            "credential_source": "session_memory",
            "tier": _optional_service_string(minted.get("tier"), 32) or "sandbox",
            "expires_at": _safe_scalar(minted.get("expires_at")),
            "limits": safe_limits,
            "next": "Call create_bot_match or join_matchmaking; no credential argument is needed.",
        }
    )


def tool_create_bot_match(args: Mapping[str, Any]) -> dict[str, Any]:
    body: dict[str, Any] = {}
    for field in ("deck", "agent_id"):
        value = args.get(field)
        if value is not None:
            ensure_no_secret(value, field)
            body[field] = value
    created = json_request(
        "POST",
        "/api/agent/match/create-bot",
        body=body,
        bearer=credentials().require_api_key(),
    )
    delivery = _remember_match_delivery(created)
    return public_result(
        {
            **delivery,
            "bot_seat": _safe_seat(created.get("bot_seat")),
            "human_url": _spectator_url(created),
            "credential_source": "session_memory",
            "next": (
                "Call get_match_state with this match_id and seat; the stored seat credential "
                "will be applied internally."
            ),
        }
    )


def tool_play_eigendark(args: Mapping[str, Any]) -> dict[str, Any]:
    """Cold-start an anonymous match without exposing onboarding to the model."""

    store = credentials()
    if store.api_key() is None:
        tool_onboard_sandbox({"name": "ChatGPT"})
    created = tool_create_bot_match({"agent_id": f"chatgpt-{secrets.token_hex(4)}"})
    state = tool_get_match_state(
        {
            "match_id": created["match_id"],
            "seat": created["seat"],
            "since_seq": 0,
            "advance_bot": False,
        }
    )
    return {**state, **created}


def tool_get_eigendark_game(args: Mapping[str, Any]) -> dict[str, Any]:
    """Read match state without advancing either seat."""

    return tool_get_match_state(
        {
            "match_id": args["match_id"],
            "seat": args["seat"],
            "since_seq": args.get("since_seq", 0),
            "advance_bot": False,
        }
    )


def tool_join_matchmaking(args: Mapping[str, Any]) -> dict[str, Any]:
    body = dict(args)
    ensure_no_secret(body, "matchmaking fields")
    queued = json_request(
        "POST",
        "/api/agent/matchmaking/join",
        body=body,
        bearer=credentials().require_api_key(),
    )
    return _matchmaking_result(queued, require_ticket_when_waiting=True)


def tool_matchmaking_status(args: Mapping[str, Any]) -> dict[str, Any]:
    status = json_request(
        "POST",
        "/api/agent/matchmaking/status",
        body={"ticket_secret": credentials().require_ticket()},
        bearer=credentials().require_api_key(),
    )
    return _matchmaking_result(status, require_ticket_when_waiting=False)


def tool_leave_matchmaking(args: Mapping[str, Any]) -> dict[str, Any]:
    result = json_request(
        "POST",
        "/api/agent/matchmaking/leave",
        body={"ticket_secret": credentials().require_ticket()},
        bearer=credentials().require_api_key(),
    )
    credentials().clear_ticket()
    status = _optional_service_string(result.get("status"), 32) or "cancelled"
    return public_result({"status": status})


def tool_get_match_state(args: Mapping[str, Any]) -> dict[str, Any]:
    match_id = args["match_id"]
    seat = args["seat"]
    ensure_no_secret(match_id, "match_id")
    body: dict[str, Any] = {
        "seat": seat,
        "token": credentials().seat_token(match_id, seat),
        "advance_bot": args.get("advance_bot", True),
    }
    if "since_seq" in args:
        body["since_seq"] = args["since_seq"]
    state = json_request("POST", _match_path(match_id, "state"), body=body)
    return public_result(state)


def tool_submit_action(args: Mapping[str, Any]) -> dict[str, Any]:
    match_id = args["match_id"]
    seat = args["seat"]
    action_args = dict(args.get("args") or {})
    ensure_no_secret(match_id, "match_id")
    ensure_no_secret(action_args, "action args")
    body: dict[str, Any] = {
        "seat": seat,
        "token": credentials().seat_token(match_id, seat),
        "kind": args["kind"],
        "args": action_args,
        "pace_bot": args.get("pace_bot", True),
    }
    if "since_seq" in args:
        body["since_seq"] = args["since_seq"]
    result = json_request("POST", _match_path(match_id, "action"), body=body)
    return public_result(result)


def tool_summarize_state(args: Mapping[str, Any]) -> dict[str, Any]:
    state = args["state"]
    if not isinstance(state, Mapping):  # schema validation is defense in depth
        raise ToolError("state must be an object")
    visible_value = state.get("state", state)
    if not isinstance(visible_value, Mapping):
        raise ToolError("state.state must be an object when present")
    players = visible_value.get("players", [])
    if not isinstance(players, list) or any(not isinstance(player, Mapping) for player in players):
        raise ToolError("state players must be an array of objects")
    legal = args.get("legal_actions", state.get("legal_actions", []))
    if not isinstance(legal, list) or any(not isinstance(action, Mapping) for action in legal):
        raise ToolError("legal_actions must be an array of objects")

    def first_present(*values: Any) -> Any:
        return next((value for value in values if value is not None), None)

    return public_result(
        {
            "match_id": first_present(state.get("match_id"), visible_value.get("match_id")),
            "status": first_present(state.get("match_status"), visible_value.get("status")),
            "your_turn": state.get("your_turn"),
            "active_idx": first_present(state.get("active_idx"), visible_value.get("active_idx")),
            "round": visible_value.get("round"),
            "turn": visible_value.get("turn"),
            "players": players,
            "legal_actions": legal,
        }
    )


def tool_share_replay(args: Mapping[str, Any]) -> dict[str, Any]:
    match_id = args["match_id"]
    seat = args["seat"]
    ensure_no_secret(match_id, "match_id")
    body: dict[str, Any] = {"token": credentials().spectator_token(match_id, seat)}
    if "ttl_minutes" in args:
        body["ttl_minutes"] = args["ttl_minutes"]
    share = json_request("POST", _match_path(match_id, "share"), body=body)
    share_id = _optional_service_string(share.get("share_id") or share.get("id"), 128)
    return public_result(
        {
            "share_id": share_id,
            "human_url": _safe_public_url(share.get("watch_url") or share.get("url")),
            "status": _optional_service_string(share.get("status"), 32),
            "expires_at": _safe_scalar(share.get("expires_at")),
            "note": "This is a read-only link intended for sharing with your operator.",
        }
    )


def tool_get_standing(args: Mapping[str, Any]) -> dict[str, Any]:
    agent_id = args["agent_id"]
    ensure_no_secret(agent_id, "agent_id")
    document = json_request("GET", "/api/agent/ladder")
    entries = document.get("entries", [])
    if not isinstance(entries, list) or len(entries) > 2_000:
        raise ToolError("The ladder response had an unexpected shape")
    entry = next(
        (
            item
            for item in entries
            if isinstance(item, Mapping) and item.get("agent_id") == agent_id
        ),
        None,
    )
    season = _safe_scalar(document.get("season"))
    if entry is None:
        return public_result(
            {
                "agent_id": agent_id,
                "ranked": False,
                "season": season,
                "ladder_url": f"{validated_base_url()}/ladder",
            }
        )
    fields = {
        "rank": entry.get("rank"),
        "rating": entry.get("elo_effective", entry.get("elo")),
        "raw_elo": entry.get("elo"),
        "idle_decay": entry.get("decay", 0),
        "wins": entry.get("wins"),
        "losses": entry.get("losses"),
        "matches": entry.get("matches"),
    }
    return public_result(
        {
            "agent_id": agent_id,
            "ranked": True,
            "season": season,
            **{key: _safe_scalar(value) for key, value in fields.items()},
            "ladder_url": f"{validated_base_url()}/ladder",
        }
    )


def _matchmaking_result(
    payload: Mapping[str, Any], *, require_ticket_when_waiting: bool
) -> dict[str, Any]:
    status = _required_service_string(payload, "status", max_length=32)
    if status not in {"waiting", "provisioning", "matched", "cancelled", "failed"}:
        raise ToolError("The matchmaking service returned an unknown status")
    ticket = payload.get("ticket_secret")
    if isinstance(ticket, str) and ticket:
        credentials().remember_ticket(ticket)
    elif require_ticket_when_waiting and status in {"waiting", "provisioning"}:
        raise ToolError("The matchmaking service did not return a private ticket")

    result: dict[str, Any] = {
        "status": status,
        "expires_at": _safe_scalar(payload.get("expires_at")),
        "poll_after_ms": _safe_bounded_int(payload.get("poll_after_ms"), 100, 60_000),
    }
    if status == "matched":
        match = payload.get("match")
        if not isinstance(match, Mapping):
            raise ToolError("The matchmaking service did not return match credentials")
        result["match"] = _remember_match_delivery(match)
        result["human_url"] = _spectator_url(match)
        credentials().clear_ticket()
    elif status in {"cancelled", "failed"}:
        credentials().clear_ticket()
    else:
        result["next"] = "Call matchmaking_status after poll_after_ms."
    return public_result(result)


def _remember_match_delivery(payload: Mapping[str, Any]) -> dict[str, Any]:
    match_id = _required_service_string(payload, "match_id", max_length=256)
    seat = _safe_seat(payload.get("seat"))
    if seat is None:
        raise ToolError("The Eigendark service returned an invalid seat")
    token = _required_service_string(payload, "token", max_length=4096)
    spectator = payload.get("spectator_token") or payload.get("review_key")
    if spectator is not None and not isinstance(spectator, str):
        raise ToolError("The Eigendark service returned an invalid spectator credential")
    credentials().remember_match(match_id, seat, token, spectator)
    return {"match_id": match_id, "seat": seat, "credential_source": "session_memory"}


def _spectator_url(payload: Mapping[str, Any]) -> str | None:
    spectator = payload.get("spectator")
    if isinstance(spectator, Mapping):
        return _safe_public_url(spectator.get("human_url") or spectator.get("watch_url"))
    return _safe_public_url(payload.get("human_url") or payload.get("watch_url"))


def _safe_public_url(value: Any) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 2_048:
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    base_url = validated_base_url()
    absolute = urllib.parse.urljoin(f"{base_url}/", value)
    try:
        base = urllib.parse.urlsplit(base_url)
        parsed = urllib.parse.urlsplit(absolute)
        base_port = base.port or (443 if base.scheme == "https" else 80)
        parsed_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return None
    same_origin = (
        parsed.scheme == base.scheme
        and parsed.hostname == base.hostname
        and parsed_port == base_port
    )
    production_alias = (
        base.hostname in PRODUCTION_HOSTS
        and parsed.hostname in PRODUCTION_HOSTS
        and parsed.scheme == base.scheme == "https"
        and parsed_port == base_port == 443
    )
    if (
        not (same_origin or production_alias)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.path not in URL_SAFE_SHARE_PATHS
    ):
        return None
    try:
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True, max_num_fields=8)
    except ValueError:
        return None
    if any(key not in URL_SAFE_SHARE_QUERY_KEYS for key in query):
        return None
    if any(len(item) > 256 for values in query.values() for item in values):
        return None
    return absolute


def _match_path(match_id: str, operation: str) -> str:
    if operation not in {"state", "action", "share"}:
        raise ToolError("Internal match operation was rejected")
    return f"/api/agent/match/{urllib.parse.quote(match_id, safe='')}/{operation}"


def _required_service_mapping(payload: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = payload.get(key)
    if not isinstance(value, Mapping):
        raise ToolError("The Eigendark service returned an unexpected response")
    return value


def _required_service_string(payload: Mapping[str, Any], key: str, *, max_length: int) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise ToolError("The Eigendark service returned an unexpected response")
    return value


def _optional_service_string(value: Any, max_length: int) -> str | None:
    if isinstance(value, str) and value and len(value) <= max_length:
        return redact_text(value)
    return None


def _safe_seat(value: Any) -> int | None:
    return value if type(value) is int and value in {0, 1} else None


def _is_plain_number(value: Any) -> bool:
    return (type(value) is int or type(value) is float) and not isinstance(value, bool)


def _safe_scalar(value: Any) -> str | int | float | bool | None:
    if value is None or isinstance(value, bool):
        return value
    if type(value) is int or type(value) is float:
        return value
    if isinstance(value, str):
        return redact_text(value[:256])
    return None


def _safe_bounded_int(value: Any, minimum: int, maximum: int) -> int | None:
    return value if type(value) is int and minimum <= value <= maximum else None


TOOL_DEFINITIONS = (
    ToolDefinition(
        "agent_protocol_guide",
        "Agent protocol guide",
        "Return the safe Eigendark play flow and action vocabulary. " + UNTRUSTED_DATA_NOTICE,
        _object_schema({}),
        tool_agent_protocol_guide,
        read_only=True,
        idempotent=True,
        open_world=False,
    ),
    ToolDefinition(
        "onboard_sandbox",
        "Onboard a sandbox agent",
        "Mint an expiring sandbox API key, retain it only in process memory, and return no secret.",
        _object_schema({"name": {**SHORT_STRING, "maxLength": 64}}),
        tool_onboard_sandbox,
    ),
    ToolDefinition(
        "create_bot_match",
        "Create a bot match",
        "Create a house-bot match and retain the seat capability only in process memory. "
        + UNTRUSTED_DATA_NOTICE,
        _object_schema(
            {
                "deck": SHORT_STRING,
                "agent_id": {"type": "string", "pattern": AGENT_ID_PATTERN, "maxLength": 48},
            }
        ),
        tool_create_bot_match,
    ),
    ToolDefinition(
        "join_matchmaking",
        "Join public matchmaking",
        "Join public matchmaking; the private ticket remains in process memory. "
        + UNTRUSTED_DATA_NOTICE,
        {
            **_object_schema(
                {
                    "agent_id": {
                        "type": "string",
                        "pattern": AGENT_ID_PATTERN,
                        "maxLength": 48,
                    },
                    "deck": SHORT_STRING,
                    "card_ids": ID_ARRAY,
                }
            ),
            "not": {"required": ["deck", "card_ids"]},
        },
        tool_join_matchmaking,
    ),
    ToolDefinition(
        "matchmaking_status",
        "Poll matchmaking",
        "Poll the in-memory private matchmaking ticket. " + UNTRUSTED_DATA_NOTICE,
        _object_schema({}),
        tool_matchmaking_status,
    ),
    ToolDefinition(
        "leave_matchmaking",
        "Leave matchmaking",
        "Cancel the in-memory matchmaking ticket while it is waiting.",
        _object_schema({}),
        tool_leave_matchmaking,
        destructive=True,
    ),
    ToolDefinition(
        "get_match_state",
        "Get match state",
        "Read the seat-redacted state. By default this may advance a paced house bot. "
        + UNTRUSTED_DATA_NOTICE,
        _object_schema(
            {
                "match_id": STRING_ID,
                "seat": {"type": "integer", "enum": [0, 1]},
                "since_seq": {"type": "integer", "minimum": 0, "maximum": 2_147_483_647},
                "advance_bot": {"type": "boolean"},
            },
            required=("match_id", "seat"),
        ),
        tool_get_match_state,
        idempotent=False,
    ),
    ToolDefinition(
        "submit_action",
        "Submit a match action",
        "Submit one schema-validated kind/args pair copied from legal_actions. "
        + UNTRUSTED_DATA_NOTICE,
        _action_input_schema(),
        tool_submit_action,
        destructive=True,
    ),
    ToolDefinition(
        "summarize_state",
        "Summarize match state",
        "Condense a state result without making a network request. " + UNTRUSTED_DATA_NOTICE,
        _object_schema(
            {
                "state": {"type": "object", "maxProperties": 512},
                "legal_actions": {"type": "array", "maxItems": 2_000},
            },
            required=("state",),
        ),
        tool_summarize_state,
        read_only=True,
        idempotent=True,
        open_world=False,
    ),
    ToolDefinition(
        "share_replay",
        "Share a replay",
        "Create a read-only spectator link using an internally held match capability.",
        _object_schema(
            {
                "match_id": STRING_ID,
                "seat": {"type": "integer", "enum": [0, 1]},
                "ttl_minutes": {"type": "integer", "minimum": 5, "maximum": 10_080},
            },
            required=("match_id", "seat"),
        ),
        tool_share_replay,
    ),
    ToolDefinition(
        "get_standing",
        "Get ladder standing",
        "Read one public agent ladder standing. " + UNTRUSTED_DATA_NOTICE,
        _object_schema(
            {
                "agent_id": {
                    "type": "string",
                    "pattern": AGENT_ID_PATTERN,
                    "maxLength": 48,
                }
            },
            required=("agent_id",),
        ),
        tool_get_standing,
        read_only=True,
        idempotent=True,
    ),
)

PUBLIC_TOOL_DEFINITIONS = (
    ToolDefinition(
        "play_eigendark",
        "Play Eigendark",
        "Start an anonymous Eigendark game against the house bot when the user asks to "
        "play Eigendark. This creates a publicly viewable match and returns its live, "
        "read-only review link. No account, key, invite, or setup is needed. "
        + UNTRUSTED_DATA_NOTICE,
        _object_schema({}),
        tool_play_eigendark,
        destructive=False,
        open_world=True,
    ),
    ToolDefinition(
        "get_eigendark_game",
        "Get Eigendark game",
        "Read the current seat-redacted Eigendark game without advancing it. Use this only to "
        "recover or refresh a game already started in this conversation. " + UNTRUSTED_DATA_NOTICE,
        _object_schema(
            {
                "match_id": STRING_ID,
                "seat": {"type": "integer", "enum": [0, 1]},
                "since_seq": {"type": "integer", "minimum": 0, "maximum": 2_147_483_647},
            },
            required=("match_id", "seat"),
        ),
        tool_get_eigendark_game,
        read_only=True,
        idempotent=True,
        open_world=False,
    ),
    ToolDefinition(
        "take_eigendark_turn",
        "Take Eigendark turn",
        "Apply exactly one legal action to the anonymous Eigendark game. Copy kind and args "
        "from the latest legal_actions, choose strategically, and continue until match_status "
        "is complete. The move updates a publicly viewable match. " + UNTRUSTED_DATA_NOTICE,
        _action_input_schema(),
        tool_submit_action,
        destructive=False,
        open_world=True,
    ),
)

TOOLS = {
    definition.name: definition for definition in (*TOOL_DEFINITIONS, *PUBLIC_TOOL_DEFINITIONS)
}

for _definition in (*TOOL_DEFINITIONS, *PUBLIC_TOOL_DEFINITIONS):
    Draft202012Validator.check_schema(_definition.input_schema)
Draft202012Validator.check_schema(OUTPUT_BASE)


def validate_tool_input(definition: ToolDefinition, arguments: Mapping[str, Any]) -> None:
    """Validate without echoing an attacker-controlled instance in an error."""

    error = next(Draft202012Validator(definition.input_schema).iter_errors(arguments), None)
    if error is not None:
        raise ToolError("Tool input failed its published JSON schema")


def invoke_tool(name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
    definition = TOOLS.get(name)
    if definition is None:
        raise ToolError("Unknown tool")
    validate_tool_input(definition, arguments)
    try:
        result = definition.handler(arguments)
        if not isinstance(result, Mapping):
            raise ToolError("The tool returned an invalid result shape")
        # Central enforcement prevents future handlers from accidentally
        # omitting redaction or the untrusted-data notice.
        return public_result(result)
    except ToolError:
        raise
    except Exception as exc:  # keep implementation details and inputs out of MCP output
        LOGGER.error("Unhandled tool failure in %s (%s)", name, type(exc).__name__)
        raise ToolError(
            "The tool failed safely; no credential or internal detail was returned"
        ) from exc
