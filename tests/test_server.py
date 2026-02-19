from __future__ import annotations

import pytest

from gcc_mcp.runtime import (
    get_runtime_defaults,
    get_runtime_security_defaults,
    is_loopback_host,
    validate_streamable_http_binding,
)


def test_validated_runtime_defaults_ok(monkeypatch) -> None:
    monkeypatch.setenv("GCC_MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("GCC_MCP_HOST", "127.0.0.1")
    monkeypatch.setenv("GCC_MCP_PORT", "9000")

    transport, host, port = get_runtime_defaults()
    assert transport == "streamable-http"
    assert host == "127.0.0.1"
    assert port == 9000


def test_validated_runtime_defaults_invalid_transport(monkeypatch) -> None:
    monkeypatch.setenv("GCC_MCP_TRANSPORT", "tcp")
    with pytest.raises(ValueError):
        get_runtime_defaults()


def test_validated_runtime_defaults_invalid_port(monkeypatch) -> None:
    monkeypatch.setenv("GCC_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("GCC_MCP_PORT", "not-a-number")
    with pytest.raises(ValueError):
        get_runtime_defaults()


def test_validated_runtime_defaults_public_host_requires_opt_in() -> None:
    with pytest.raises(ValueError):
        get_runtime_defaults(
            env={
                "GCC_MCP_TRANSPORT": "streamable-http",
                "GCC_MCP_HOST": "0.0.0.0",
                "GCC_MCP_PORT": "8000",
            }
        )


def test_validated_runtime_defaults_public_host_allowed_with_opt_in() -> None:
    transport, host, port = get_runtime_defaults(
        env={
            "GCC_MCP_TRANSPORT": "streamable-http",
            "GCC_MCP_HOST": "0.0.0.0",
            "GCC_MCP_PORT": "8000",
            "GCC_MCP_ALLOW_PUBLIC_HTTP": "true",
        }
    )
    assert transport == "streamable-http"
    assert host == "0.0.0.0"
    assert port == 8000


def test_validated_runtime_defaults_explicit_empty_env_mapping(monkeypatch) -> None:
    monkeypatch.setenv("GCC_MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("GCC_MCP_HOST", "10.0.0.1")
    monkeypatch.setenv("GCC_MCP_PORT", "9090")

    transport, host, port = get_runtime_defaults(env={})
    assert transport == "stdio"
    assert host == "127.0.0.1"
    assert port == 8000


@pytest.mark.parametrize("port", ["0", "65536"])
def test_validated_runtime_defaults_invalid_port_range(port: str) -> None:
    with pytest.raises(ValueError):
        get_runtime_defaults(
            env={
                "GCC_MCP_TRANSPORT": "stdio",
                "GCC_MCP_HOST": "127.0.0.1",
                "GCC_MCP_PORT": port,
            }
        )


def test_runtime_security_defaults_and_bool_parsing() -> None:
    allow_public_http, audit_path, audit_redact = get_runtime_security_defaults(
        env={
            "GCC_MCP_ALLOW_PUBLIC_HTTP": "yes",
            "GCC_MCP_AUDIT_LOG": "logs/gcc-audit.jsonl",
            "GCC_MCP_AUDIT_REDACT": "false",
        }
    )
    assert allow_public_http is True
    assert audit_path == "logs/gcc-audit.jsonl"
    assert audit_redact is False


def test_runtime_security_defaults_invalid_bool() -> None:
    with pytest.raises(ValueError):
        get_runtime_security_defaults(env={"GCC_MCP_ALLOW_PUBLIC_HTTP": "sometimes"})


@pytest.mark.parametrize(
    ("transport", "host", "allow_public_http", "expect_error"),
    [
        ("stdio", "0.0.0.0", False, False),
        ("streamable-http", "127.0.0.1", False, False),
        ("streamable-http", "localhost", False, False),
        ("streamable-http", "10.0.0.5", False, True),
        ("streamable-http", "10.0.0.5", True, False),
    ],
)
def test_validate_streamable_http_binding(
    transport: str,
    host: str,
    allow_public_http: bool,
    expect_error: bool,
) -> None:
    if expect_error:
        with pytest.raises(ValueError):
            validate_streamable_http_binding(
                transport=transport,
                host=host,
                allow_public_http=allow_public_http,
            )
    else:
        validate_streamable_http_binding(
            transport=transport,
            host=host,
            allow_public_http=allow_public_http,
        )


@pytest.mark.parametrize(
    ("host", "is_loopback"),
    [
        ("127.0.0.1", True),
        ("localhost", True),
        ("::1", True),
        ("0.0.0.0", False),
        ("10.0.0.7", False),
    ],
)
def test_is_loopback_host(host: str, is_loopback: bool) -> None:
    assert is_loopback_host(host) is is_loopback
