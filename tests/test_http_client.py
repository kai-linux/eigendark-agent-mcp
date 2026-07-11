from __future__ import annotations

import io
import json
import urllib.error
import urllib.request
from email.message import Message

import pytest

from eigendark_agent_mcp import http_client
from eigendark_agent_mcp.errors import ToolError


def headers(content_type: str = "application/json", content_length: int | None = None) -> Message:
    result = Message()
    if content_type:
        result["Content-Type"] = content_type
    if content_length is not None:
        result["Content-Length"] = str(content_length)
    return result


class FakeResponse:
    def __init__(self, payload: bytes, response_headers: Message | None = None):
        self._body = io.BytesIO(payload)
        self.headers = response_headers if response_headers is not None else headers()

    def read(self, size: int = -1) -> bytes:
        return self._body.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeOpener:
    def __init__(self, outcome):
        self.outcome = outcome
        self.request: urllib.request.Request | None = None
        self.timeout: float | None = None

    def open(self, request: urllib.request.Request, timeout: float):
        self.request = request
        self.timeout = timeout
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


def install_opener(monkeypatch: pytest.MonkeyPatch, outcome) -> FakeOpener:
    opener = FakeOpener(outcome)
    monkeypatch.setattr(http_client, "_opener", lambda base_url: opener)
    return opener


def test_json_request_uses_bounded_json_body_and_unredirected_auth(
    monkeypatch: pytest.MonkeyPatch,
):
    opener = install_opener(
        monkeypatch,
        FakeResponse(b'{"match_id":"M","token":"seat_raw_credential"}'),
    )
    result = http_client.json_request(
        "POST", "/api/agent/test", body={"seat": 0}, bearer="api_bearer_credential"
    )
    assert result["token"] == "seat_raw_credential"  # trusted handler consumes this
    assert opener.request is not None
    assert opener.request.full_url == "https://www.eigendark.com/api/agent/test"
    assert "api_bearer_credential" not in opener.request.full_url
    assert opener.request.unredirected_hdrs["Authorization"] == "Bearer api_bearer_credential"
    assert json.loads(opener.request.data) == {"seat": 0}
    assert opener.timeout == 20.0


def test_success_requires_json_mapping(monkeypatch: pytest.MonkeyPatch):
    for response, expected in (
        (FakeResponse(b""), {}),
        (FakeResponse(b'{"ok":true}', headers("application/problem+json")), {"ok": True}),
    ):
        install_opener(monkeypatch, response)
        assert http_client.json_request("GET", "/api/agent/test") == expected

    install_opener(monkeypatch, FakeResponse(b"[]"))
    with pytest.raises(ToolError, match="unexpected JSON shape"):
        http_client.json_request("GET", "/api/agent/test")
    install_opener(monkeypatch, FakeResponse(b"not json", headers("text/plain")))
    with pytest.raises(ToolError, match="non-JSON"):
        http_client.json_request("GET", "/api/agent/test")


def test_response_size_limits_use_header_and_actual_bytes(monkeypatch: pytest.MonkeyPatch):
    too_large = http_client.MAX_RESPONSE_BYTES + 1
    install_opener(monkeypatch, FakeResponse(b"{}", headers(content_length=too_large)))
    with pytest.raises(ToolError, match="size limit"):
        http_client.json_request("GET", "/api/agent/test")
    install_opener(monkeypatch, FakeResponse(b"x" * too_large))
    with pytest.raises(ToolError, match="size limit"):
        http_client.json_request("GET", "/api/agent/test")


def test_http_error_is_structured_and_reflected_secrets_are_redacted(
    monkeypatch: pytest.MonkeyPatch,
):
    secret = "api_bearer_credential"
    body = json.dumps(
        {
            "error": f"failed for {secret}",
            "message": "internal infrastructure detail must not escape",
            "accessToken": secret,
        }
    ).encode()
    error = urllib.error.HTTPError(
        "https://www.eigendark.com/api/agent/test",
        403,
        "Forbidden",
        headers(),
        io.BytesIO(body),
    )
    install_opener(monkeypatch, error)
    with pytest.raises(ToolError) as caught:
        http_client.json_request("GET", "/api/agent/test", bearer=secret)
    rendered = str(caught.value)
    assert secret not in rendered
    assert "403" in rendered
    assert "[redacted]" in rendered
    assert "infrastructure detail" not in rendered
    assert "security_notice" in rendered


def test_redirect_is_never_followed_or_exposed(monkeypatch: pytest.MonkeyPatch):
    error = urllib.error.HTTPError(
        "https://www.eigendark.com/api/agent/test",
        302,
        "Found",
        headers(),
        io.BytesIO(b""),
    )
    install_opener(monkeypatch, error)
    with pytest.raises(ToolError, match="redirect"):
        http_client.json_request("POST", "/api/agent/test", bearer="ed_secret_value")


@pytest.mark.parametrize(
    "error",
    [urllib.error.URLError("network detail"), TimeoutError()],
)
def test_network_failures_do_not_expose_exception_detail(
    monkeypatch: pytest.MonkeyPatch, error: BaseException
):
    install_opener(monkeypatch, error)
    with pytest.raises(ToolError, match="failed or timed out") as caught:
        http_client.json_request("GET", "/api/agent/test")
    assert "network detail" not in str(caught.value)


@pytest.mark.parametrize(
    "path",
    [
        "api/agent/test",
        "//evil.test/api/agent/test",
        "/api/other/test",
        "/api/agent/test?token=secret",
        "/api/agent/test#fragment",
        "/api/agent/\\evil",
        "/api/agent/test\nheader",
    ],
)
def test_path_validation_rejects_url_confusion(path: str):
    with pytest.raises(ToolError, match="path"):
        http_client.json_request("GET", path)


def test_request_validation_rejects_methods_and_oversized_or_non_json_bodies(
    monkeypatch: pytest.MonkeyPatch,
):
    with pytest.raises(ToolError, match="method"):
        http_client.json_request("DELETE", "/api/agent/test")
    with pytest.raises(ToolError, match="valid JSON"):
        http_client.json_request("POST", "/api/agent/test", body={"bad": object()})
    with pytest.raises(ToolError, match="size limit"):
        http_client.json_request(
            "POST", "/api/agent/test", body={"large": "x" * http_client.MAX_REQUEST_BYTES}
        )


def test_loopback_opener_disables_proxies(monkeypatch: pytest.MonkeyPatch):
    captured: list[urllib.request.BaseHandler] = []
    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *handlers_: captured.extend(handlers_) or object(),
    )
    http_client._opener("http://localhost:5000")
    proxy = next(
        handler for handler in captured if isinstance(handler, urllib.request.ProxyHandler)
    )
    assert proxy.proxies == {}
    captured.clear()
    http_client._opener("https://www.eigendark.com")
    assert not any(isinstance(handler, urllib.request.ProxyHandler) for handler in captured)
