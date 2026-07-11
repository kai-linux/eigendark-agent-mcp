from __future__ import annotations

import math

import pytest

from eigendark_agent_mcp import config
from eigendark_agent_mcp.errors import ToolError


def test_default_configuration():
    assert config.configured_base_url() == config.DEFAULT_BASE_URL
    assert config.configured_timeout() == 20.0
    assert config.validated_base_url() == config.DEFAULT_BASE_URL


def test_aliases_and_empty_values(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("EIGENDARK_BASE_URL", "")
    monkeypatch.setenv("ED_BASE_URL", "http://localhost:5000/")
    monkeypatch.setenv("ED_TIMEOUT_SECONDS", "0.25")
    assert config.configured_base_url() == "http://localhost:5000"
    assert config.configured_timeout() == 0.25


@pytest.mark.parametrize("value", ["nope", "0", "-1", "121", "nan", "inf", "-inf"])
def test_timeout_rejects_invalid_and_non_finite_values(monkeypatch: pytest.MonkeyPatch, value: str):
    monkeypatch.setenv("EIGENDARK_TIMEOUT_SECONDS", value)
    with pytest.raises(ToolError, match="TIMEOUT_SECONDS"):
        config.configured_timeout()


@pytest.mark.parametrize(
    "url",
    [
        "https://eigendark.com",
        "https://www.eigendark.com",
        "https://www.eigendark.com:443",
        "http://localhost:8080",
        "https://127.0.0.1:9443",
        "http://[::1]:5000",
    ],
)
def test_allowed_base_urls(monkeypatch: pytest.MonkeyPatch, url: str):
    monkeypatch.setenv("EIGENDARK_BASE_URL", url)
    assert config.validated_base_url() == url


@pytest.mark.parametrize(
    "url",
    [
        "http://www.eigendark.com",
        "https://www.eigendark.com:444",
        "https://user@www.eigendark.com",
        "https://user:pass@www.eigendark.com",
        "https://www.eigendark.com/api",
        "https://www.eigendark.com?token=value",
        "https://www.eigendark.com#fragment",
        "https://www.eigendark.com\\@example.test",
        "ftp://localhost/resource",
        "https://",
        "https://www.eigendark.com:not-a-port",
        "https://example.test",
    ],
)
def test_base_url_fails_closed(monkeypatch: pytest.MonkeyPatch, url: str):
    monkeypatch.setenv("EIGENDARK_BASE_URL", url)
    with pytest.raises(ToolError):
        config.validated_base_url()


def test_explicit_remote_override_still_requires_https(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("EIGENDARK_MCP_ALLOW_UNTRUSTED_BASE_URL", "1")
    monkeypatch.setenv("EIGENDARK_BASE_URL", "http://example.test")
    with pytest.raises(ToolError, match="HTTPS"):
        config.validated_base_url()
    monkeypatch.setenv("EIGENDARK_BASE_URL", "https://example.test:8443")
    assert config.validated_base_url() == "https://example.test:8443"


def test_loopback_detection():
    assert config.is_loopback_base_url("http://localhost:1234")
    assert config.is_loopback_base_url("https://[::1]")
    assert not config.is_loopback_base_url("https://www.eigendark.com")


def test_timeout_constant_is_finite():
    assert math.isfinite(config.DEFAULT_TIMEOUT_SECONDS)
