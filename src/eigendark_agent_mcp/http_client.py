"""Small fail-closed JSON client for the documented Eigendark Agent API."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Mapping
from typing import Any

from . import __version__
from .config import configured_timeout, is_loopback_base_url, validated_base_url
from .errors import ToolError
from .security import UNTRUSTED_DATA_NOTICE, sanitize_public

MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    """Never replay credentials or request bodies to a redirect target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


def _opener(base_url: str) -> urllib.request.OpenerDirector:
    handlers: list[urllib.request.BaseHandler] = [RejectRedirects()]
    if is_loopback_base_url(base_url):
        # Environment proxy variables must never turn a loopback test endpoint
        # into an external credential hop.
        handlers.insert(0, urllib.request.ProxyHandler({}))
    return urllib.request.build_opener(*handlers)


def _safe_path(path: str) -> str:
    if (
        not isinstance(path, str)
        or not path.startswith("/api/agent/")
        or path.startswith("//")
        or "?" in path
        or "#" in path
        or "\\" in path
        or any(ord(char) < 32 or ord(char) == 127 for char in path)
    ):
        raise ToolError("Internal API path was rejected")
    return path


def json_request(
    method: str,
    path: str,
    *,
    body: Mapping[str, Any] | None = None,
    bearer: str | None = None,
) -> dict[str, Any]:
    if method not in {"GET", "POST"}:
        raise ToolError("Internal HTTP method was rejected")
    base_url = validated_base_url()
    url = f"{base_url}{_safe_path(path)}"
    headers = {
        "Accept": "application/json",
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
        "User-Agent": f"eigendark-agent-mcp/{__version__}",
    }
    data: bytes | None = None
    if body is not None:
        try:
            data = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ToolError("Internal request body was not valid JSON") from exc
        if len(data) > MAX_REQUEST_BYTES:
            raise ToolError("Request body exceeds the safe size limit")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    if bearer:
        # unredirected_header prevents urllib from automatically replaying this
        # credential even if redirect handling changes later.
        request.add_unredirected_header("Authorization", f"Bearer {bearer}")

    try:
        with _opener(base_url).open(request, timeout=configured_timeout()) as response:
            payload = _bounded_read(response)
            if not payload:
                return {}
            _require_json_content_type(response.headers)
            return _decode_mapping(payload)
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            raise ToolError(f"Eigendark refused an unexpected HTTP redirect ({exc.code})") from exc
        detail: Any = {"error": "Eigendark request failed"}
        try:
            payload = _bounded_read(exc)
            if payload and _is_json_content_type(exc.headers):
                detail = json.loads(payload.decode("utf-8"))
        except (ToolError, UnicodeDecodeError, ValueError, OverflowError, RecursionError):
            detail = {"error": "Eigendark request failed"}
        remote_error = detail.get("error") if isinstance(detail, Mapping) else None
        if not isinstance(remote_error, str) or not remote_error:
            remote_error = "Eigendark request failed"
        safe_error = sanitize_public(remote_error[:256], extra_sensitive=(bearer,))
        raise ToolError(
            json.dumps(
                {
                    "status": exc.code,
                    "error": safe_error,
                    "security_notice": UNTRUSTED_DATA_NOTICE,
                },
                sort_keys=True,
            )
        ) from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise ToolError("The Eigendark request failed or timed out") from exc
    except (UnicodeDecodeError, ValueError, OverflowError, RecursionError) as exc:
        raise ToolError("The Eigendark service returned invalid JSON") from exc


def _bounded_read(response: Any) -> bytes:
    raw_length = response.headers.get("Content-Length") if response.headers else None
    if raw_length:
        try:
            if int(raw_length) > MAX_RESPONSE_BYTES:
                raise ToolError("The Eigendark response exceeded the safe size limit")
        except ValueError:
            pass
    payload = response.read(MAX_RESPONSE_BYTES + 1)
    if len(payload) > MAX_RESPONSE_BYTES:
        raise ToolError("The Eigendark response exceeded the safe size limit")
    return payload


def _is_json_content_type(headers: Any) -> bool:
    if not headers:
        return False
    content_type = headers.get_content_type() if hasattr(headers, "get_content_type") else ""
    if content_type == "application/json" or content_type.endswith("+json"):
        return True
    raw = headers.get("Content-Type", "") if hasattr(headers, "get") else ""
    media_type = raw.split(";", 1)[0].strip().lower()
    return media_type == "application/json" or media_type.endswith("+json")


def _require_json_content_type(headers: Any) -> None:
    if not _is_json_content_type(headers):
        raise ToolError("The Eigendark service returned a non-JSON response")


def _decode_mapping(payload: bytes) -> dict[str, Any]:
    parsed = json.loads(payload.decode("utf-8"))
    if not isinstance(parsed, Mapping):
        raise ToolError("The Eigendark service returned an unexpected JSON shape")
    # Credential-bearing responses are consumed by the trusted tool layer before
    # that layer sanitizes anything returned to MCP. Never expose this raw mapping.
    return dict(parsed)
