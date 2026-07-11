"""Runtime configuration with fail-closed destination validation."""

from __future__ import annotations

import math
import os
import urllib.parse

from .errors import ToolError

DEFAULT_BASE_URL = "https://www.eigendark.com"
DEFAULT_TIMEOUT_SECONDS = 20.0
MAX_TIMEOUT_SECONDS = 120.0
PRODUCTION_HOSTS = frozenset({"eigendark.com", "www.eigendark.com"})
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def env_value(*names: str) -> str | None:
    """Return the first non-empty environment value."""

    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return None


def configured_base_url() -> str:
    raw = env_value("EIGENDARK_BASE_URL", "ED_BASE_URL") or DEFAULT_BASE_URL
    return raw.rstrip("/")


def configured_timeout() -> float:
    raw = env_value("EIGENDARK_TIMEOUT_SECONDS", "ED_TIMEOUT_SECONDS")
    if raw is None:
        return DEFAULT_TIMEOUT_SECONDS
    try:
        timeout = float(raw)
    except ValueError as exc:
        raise ToolError("EIGENDARK_TIMEOUT_SECONDS must be numeric") from exc
    if not math.isfinite(timeout) or timeout <= 0 or timeout > MAX_TIMEOUT_SECONDS:
        raise ToolError(
            "EIGENDARK_TIMEOUT_SECONDS must be greater than 0 and at most "
            f"{int(MAX_TIMEOUT_SECONDS)}"
        )
    return timeout


def allow_untrusted_base_url() -> bool:
    return env_value("EIGENDARK_MCP_ALLOW_UNTRUSTED_BASE_URL") == "1"


def validated_base_url() -> str:
    """Return a canonical-enough base URL or fail before any secret is loaded."""

    raw = configured_base_url()
    try:
        parsed = urllib.parse.urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise ToolError("EIGENDARK_BASE_URL is invalid") from exc

    host = (parsed.hostname or "").lower()
    if (
        not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or "\\" in raw
    ):
        raise ToolError("EIGENDARK_BASE_URL must contain only a scheme and host")

    if host in PRODUCTION_HOSTS:
        if parsed.scheme != "https" or port not in {None, 443}:
            raise ToolError("Eigendark production traffic requires HTTPS on port 443")
        return raw

    if host in LOOPBACK_HOSTS:
        if parsed.scheme not in {"http", "https"}:
            raise ToolError("Loopback EIGENDARK_BASE_URL must use HTTP or HTTPS")
        return raw

    if not allow_untrusted_base_url():
        raise ToolError(
            "Refusing an untrusted EIGENDARK_BASE_URL; use eigendark.com or loopback, "
            "or explicitly opt in with EIGENDARK_MCP_ALLOW_UNTRUSTED_BASE_URL=1"
        )
    if parsed.scheme != "https":
        raise ToolError("Explicitly trusted remote base URLs must still use HTTPS")
    return raw


def is_loopback_base_url(base_url: str) -> bool:
    return (urllib.parse.urlsplit(base_url).hostname or "").lower() in LOOPBACK_HOSTS
