"""Bounded, process-local credential state.

Credentials intentionally have no serialization API. They are accepted only from the
environment or trusted Eigendark responses and never cross the MCP model boundary.
"""

from __future__ import annotations

import os
import threading
import weakref
from collections import OrderedDict
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

from .config import env_value
from .errors import ToolError

MAX_MATCH_CREDENTIALS = 32


@dataclass(frozen=True, slots=True)
class MatchCredentials:
    seat_token: str
    spectator_token: str | None = None


class CredentialStore:
    """Thread-safe, bounded credentials for one MCP server process."""

    def __init__(self, max_matches: int = MAX_MATCH_CREDENTIALS) -> None:
        if max_matches < 1:
            raise ValueError("max_matches must be positive")
        self._max_matches = max_matches
        self._lock = threading.RLock()
        self._api_key: str | None = None
        self._ticket: str | None = None
        self._matches: OrderedDict[tuple[str, int], MatchCredentials] = OrderedDict()

    def remember_api_key(self, value: str) -> None:
        value = _credential(value, "API key")
        with self._lock:
            self._api_key = value

    def api_key(self) -> str | None:
        with self._lock:
            runtime = self._api_key
        value = env_value("EIGENDARK_API_KEY", "ED_API_KEY") or runtime
        return _credential(value, "API key") if value else None

    def require_api_key(self) -> str:
        value = self.api_key()
        if not value:
            raise ToolError(
                "No API key is configured; set EIGENDARK_API_KEY or call onboard_sandbox first"
            )
        return value

    def remember_ticket(self, value: str) -> None:
        value = _credential(value, "matchmaking ticket")
        with self._lock:
            self._ticket = value

    def ticket(self) -> str | None:
        with self._lock:
            return self._ticket

    def require_ticket(self) -> str:
        value = self.ticket()
        if not value:
            raise ToolError("No matchmaking ticket is active; call join_matchmaking first")
        return value

    def clear_ticket(self) -> None:
        with self._lock:
            self._ticket = None

    def remember_match(
        self,
        match_id: str,
        seat: int,
        seat_token: str,
        spectator_token: str | None = None,
    ) -> None:
        key = (_identifier(match_id, "match_id"), _seat(seat))
        creds = MatchCredentials(
            seat_token=_credential(seat_token, "seat token"),
            spectator_token=(
                _credential(spectator_token, "spectator token") if spectator_token else None
            ),
        )
        with self._lock:
            self._matches[key] = creds
            self._matches.move_to_end(key)
            while len(self._matches) > self._max_matches:
                self._matches.popitem(last=False)

    def seat_token(self, match_id: str, seat: int) -> str:
        key = (_identifier(match_id, "match_id"), _seat(seat))
        with self._lock:
            creds = self._matches.get(key)
            if creds:
                self._matches.move_to_end(key)
        value = creds.seat_token if creds else env_value("EIGENDARK_SEAT_TOKEN", "ED_SEAT_TOKEN")
        if not value:
            raise ToolError(
                "No seat credential is available for this match and seat; configure "
                "EIGENDARK_SEAT_TOKEN or create/join the match in this server process"
            )
        return _credential(value, "seat token")

    def spectator_token(self, match_id: str, seat: int) -> str:
        key = (_identifier(match_id, "match_id"), _seat(seat))
        with self._lock:
            creds = self._matches.get(key)
            if creds:
                self._matches.move_to_end(key)
        if creds and creds.spectator_token:
            return creds.spectator_token
        # The API also accepts a match capability for share creation. This remains
        # internal and is never placed in a URL or tool result.
        return self.seat_token(match_id, seat)

    def sensitive_values(self) -> tuple[str, ...]:
        values = [
            value
            for name in (
                "EIGENDARK_API_KEY",
                "ED_API_KEY",
                "EIGENDARK_SEAT_TOKEN",
                "ED_SEAT_TOKEN",
                "EIGENDARK_GPT_ACTION_KEY",
            )
            if (value := os.environ.get(name))
        ]
        with self._lock:
            values.extend(value for value in (self._api_key, self._ticket) if value)
            for creds in self._matches.values():
                values.append(creds.seat_token)
                if creds.spectator_token:
                    values.append(creds.spectator_token)
        # Preserve order while deduplicating so replacement is deterministic.
        return tuple(dict.fromkeys(values))

    def reset(self) -> None:
        """Clear process-local state. Intended for tests and orderly teardown."""

        with self._lock:
            self._api_key = None
            self._ticket = None
            self._matches.clear()


def _credential(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4096
        or any(not 33 <= ord(character) <= 126 for character in value)
    ):
        raise ToolError(f"The Eigendark service returned an invalid {label}")
    return value


def _identifier(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 256
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ToolError(f"{label} is invalid")
    return value


def _seat(value: object) -> int:
    # bool is an int subclass and must not be accepted as a seat.
    if type(value) is not int or value not in {0, 1}:
        raise ToolError("seat must be the integer 0 or 1")
    return value


CREDENTIALS = CredentialStore()

_ACTIVE_CREDENTIALS: ContextVar[CredentialStore] = ContextVar(
    "eigendark_active_credentials",
    default=CREDENTIALS,
)


def credentials() -> CredentialStore:
    """Return the credential store isolated to the current MCP session."""

    return _ACTIVE_CREDENTIALS.get()


@contextmanager
def credential_scope(store: CredentialStore) -> Iterator[None]:
    """Bind one credential store to this async/task/thread context."""

    token = _ACTIVE_CREDENTIALS.set(store)
    try:
        yield
    finally:
        _ACTIVE_CREDENTIALS.reset(token)


class SessionCredentialRegistry:
    """Allocate one bounded credential store per live MCP protocol session.

    Session objects are held weakly so an expired HTTP transport cannot leave
    credentials reachable after the SDK releases its session.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._stores: weakref.WeakKeyDictionary[object, CredentialStore] = (
            weakref.WeakKeyDictionary()
        )

    def for_session(self, session: object) -> CredentialStore:
        with self._lock:
            store = self._stores.get(session)
            if store is None:
                store = CredentialStore()
                self._stores[session] = store
            return store

    def active_count(self) -> int:
        with self._lock:
            return len(self._stores)
