from __future__ import annotations

import pytest

from gcc_mcp.runtime import (
    RuntimeAuthDefaults,
    RuntimeSecurityPolicyDefaults,
    build_http_base_url,
    get_runtime_auth_defaults,
    get_runtime_defaults,
    get_runtime_operations_defaults,
    get_runtime_path_resolution_defaults,
    get_runtime_security_policy_defaults,
    get_runtime_security_defaults,
    is_loopback_host,
    parse_csv_values,
    resolve_audit_signing_key,
    resolve_auth_metadata_urls,
    validate_runtime_auth_values,
    validate_runtime_security_policy_values,
    validate_runtime_operation_values,
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


def test_runtime_path_resolution_defaults_parsing() -> None:
    defaults = get_runtime_path_resolution_defaults(
        env={
            "GCC_MCP_PATH_MAP": (
                '[{"from":"/opt/agent/worktrees","to":"/workspace/repos"},'
                '{"from":"/srv/shared","to":"/workspace/shared"}]'
            ),
            "GCC_MCP_ALLOWED_ROOTS": "/workspace/repos,/workspace/shared",
        }
    )
    assert defaults.path_mappings == (
        ("/opt/agent/worktrees", "/workspace/repos"),
        ("/srv/shared", "/workspace/shared"),
    )
    assert defaults.allowed_roots == ("/workspace/repos", "/workspace/shared")


def test_runtime_path_resolution_defaults_rejects_relative_paths() -> None:
    with pytest.raises(ValueError):
        get_runtime_path_resolution_defaults(
            env={
                "GCC_MCP_PATH_MAP": '[{"from":"worktrees","to":"/workspace/repos"}]',
            }
        )
    with pytest.raises(ValueError):
        get_runtime_path_resolution_defaults(
            env={"GCC_MCP_ALLOWED_ROOTS": '["workspace/repos"]'}
        )


def test_runtime_operations_defaults_ok() -> None:
    rate_limit, max_chars = get_runtime_operations_defaults(
        env={
            "GCC_MCP_RATE_LIMIT_PER_MINUTE": "180",
            "GCC_MCP_AUDIT_MAX_FIELD_CHARS": "2048",
        }
    )
    assert rate_limit == 180
    assert max_chars == 2048


def test_runtime_operations_defaults_zero_disables_truncation() -> None:
    _, max_chars = get_runtime_operations_defaults(env={"GCC_MCP_AUDIT_MAX_FIELD_CHARS": "0"})
    assert max_chars == 0


def test_runtime_operations_defaults_invalid_values() -> None:
    with pytest.raises(ValueError):
        get_runtime_operations_defaults(env={"GCC_MCP_RATE_LIMIT_PER_MINUTE": "-1"})
    with pytest.raises(ValueError):
        get_runtime_operations_defaults(env={"GCC_MCP_AUDIT_MAX_FIELD_CHARS": "32"})
    with pytest.raises(ValueError):
        get_runtime_operations_defaults(env={"GCC_MCP_RATE_LIMIT_PER_MINUTE": "many"})


def test_validate_runtime_operation_values() -> None:
    validate_runtime_operation_values(rate_limit_per_minute=0, audit_max_field_chars=0)
    validate_runtime_operation_values(rate_limit_per_minute=0, audit_max_field_chars=64)
    validate_runtime_operation_values(rate_limit_per_minute=100, audit_max_field_chars=4096)
    with pytest.raises(ValueError):
        validate_runtime_operation_values(rate_limit_per_minute=-1, audit_max_field_chars=512)
    with pytest.raises(ValueError):
        validate_runtime_operation_values(rate_limit_per_minute=5, audit_max_field_chars=40)


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
        ("127.0.0.2", True),
        ("127.255.255.254", True),
        ("localhost", True),
        ("LOCALHOST", True),
        ("::1", True),
        ("[::1]", True),
        ("0.0.0.0", False),
        ("10.0.0.7", False),
    ],
)
def test_is_loopback_host(host: str, is_loopback: bool) -> None:
    assert is_loopback_host(host) is is_loopback


def _auth_defaults(**overrides) -> RuntimeAuthDefaults:
    payload = {
        "auth_mode": "off",
        "auth_token": "",
        "trusted_proxy_header": "",
        "trusted_proxy_value": "",
        "oauth2_introspection_url": "",
        "oauth2_client_id": "",
        "oauth2_client_secret": "",
        "oauth2_introspection_timeout_seconds": 5.0,
        "auth_issuer_url": "",
        "auth_resource_server_url": "",
        "auth_required_scopes": (),
    }
    payload.update(overrides)
    return RuntimeAuthDefaults(**payload)


def _policy_defaults(**overrides) -> RuntimeSecurityPolicyDefaults:
    payload = {
        "security_profile": "baseline",
        "audit_signing_key": "",
        "audit_signing_key_file": "",
        "audit_signing_key_id": "",
    }
    payload.update(overrides)
    return RuntimeSecurityPolicyDefaults(**payload)


def test_runtime_auth_defaults_parsing() -> None:
    defaults = get_runtime_auth_defaults(
        env={
            "GCC_MCP_AUTH_MODE": "oauth2",
            "GCC_MCP_OAUTH2_INTROSPECTION_URL": "https://auth.example.com/introspect",
            "GCC_MCP_OAUTH2_CLIENT_ID": "gcc-client",
            "GCC_MCP_OAUTH2_CLIENT_SECRET": " top-secret ",
            "GCC_MCP_OAUTH2_INTROSPECTION_TIMEOUT_SECONDS": "9.5",
            "GCC_MCP_AUTH_REQUIRED_SCOPES": "gcc.read,gcc.write",
        }
    )
    assert defaults.auth_mode == "oauth2"
    assert defaults.oauth2_introspection_url == "https://auth.example.com/introspect"
    assert defaults.oauth2_client_id == "gcc-client"
    assert defaults.oauth2_client_secret == "top-secret"
    assert defaults.oauth2_introspection_timeout_seconds == pytest.approx(9.5)
    assert defaults.auth_required_scopes == ("gcc.read", "gcc.write")


def test_runtime_auth_defaults_invalid_mode() -> None:
    with pytest.raises(ValueError):
        get_runtime_auth_defaults(env={"GCC_MCP_AUTH_MODE": "jwt"})


def test_runtime_security_policy_defaults_parsing() -> None:
    defaults = get_runtime_security_policy_defaults(
        env={
            "GCC_MCP_SECURITY_PROFILE": "strict",
            "GCC_MCP_AUDIT_SIGNING_KEY": " signing-key ",
            "GCC_MCP_AUDIT_SIGNING_KEY_FILE": " /tmp/audit-signing.key ",
            "GCC_MCP_AUDIT_SIGNING_KEY_ID": " key-a ",
        }
    )
    assert defaults.security_profile == "strict"
    assert defaults.audit_signing_key == "signing-key"
    assert defaults.audit_signing_key_file == "/tmp/audit-signing.key"
    assert defaults.audit_signing_key_id == "key-a"


def test_runtime_security_policy_defaults_invalid_profile() -> None:
    with pytest.raises(ValueError):
        get_runtime_security_policy_defaults(env={"GCC_MCP_SECURITY_PROFILE": "hardened"})


@pytest.mark.parametrize("timeout", ["nan", "inf", "-inf"])
def test_runtime_auth_defaults_rejects_non_finite_timeout(timeout: str) -> None:
    with pytest.raises(ValueError):
        get_runtime_auth_defaults(
            env={
                "GCC_MCP_AUTH_MODE": "oauth2",
                "GCC_MCP_OAUTH2_INTROSPECTION_URL": "https://auth.example.com/introspect",
                "GCC_MCP_OAUTH2_INTROSPECTION_TIMEOUT_SECONDS": timeout,
            }
        )


def test_validate_runtime_auth_values_off_mode_accepts_stdio() -> None:
    validate_runtime_auth_values(
        transport="stdio",
        auth_defaults=_auth_defaults(auth_mode="off"),
    )


def test_validate_runtime_auth_values_token_mode() -> None:
    with pytest.raises(ValueError):
        validate_runtime_auth_values(
            transport="stdio",
            auth_defaults=_auth_defaults(auth_mode="token", auth_token="shared"),
        )

    with pytest.raises(ValueError):
        validate_runtime_auth_values(
            transport="streamable-http",
            auth_defaults=_auth_defaults(auth_mode="token"),
        )

    validate_runtime_auth_values(
        transport="streamable-http",
        auth_defaults=_auth_defaults(auth_mode="token", auth_token="shared"),
    )


def test_validate_runtime_auth_values_trusted_proxy_header_mode() -> None:
    with pytest.raises(ValueError):
        validate_runtime_auth_values(
            transport="streamable-http",
            auth_defaults=_auth_defaults(
                auth_mode="trusted-proxy-header",
                trusted_proxy_header="",
                trusted_proxy_value="token",
            ),
        )

    with pytest.raises(ValueError):
        validate_runtime_auth_values(
            transport="streamable-http",
            auth_defaults=_auth_defaults(
                auth_mode="trusted-proxy-header",
                trusted_proxy_header="x_bad/header",
                trusted_proxy_value="token",
            ),
        )

    with pytest.raises(ValueError):
        validate_runtime_auth_values(
            transport="streamable-http",
            auth_defaults=_auth_defaults(
                auth_mode="trusted-proxy-header",
                trusted_proxy_header="x-envoy-auth",
                trusted_proxy_value="",
            ),
        )

    validate_runtime_auth_values(
        transport="streamable-http",
        auth_defaults=_auth_defaults(
            auth_mode="trusted-proxy-header",
            trusted_proxy_header="x-envoy-auth",
            trusted_proxy_value="trusted-shared-value",
        ),
    )


def test_validate_runtime_auth_values_oauth2_mode() -> None:
    with pytest.raises(ValueError):
        validate_runtime_auth_values(
            transport="streamable-http",
            auth_defaults=_auth_defaults(auth_mode="oauth2"),
        )

    with pytest.raises(ValueError):
        validate_runtime_auth_values(
            transport="streamable-http",
            auth_defaults=_auth_defaults(
                auth_mode="oauth2",
                oauth2_introspection_url="https://auth.example.com/introspect",
                oauth2_client_id="client-id",
            ),
        )

    with pytest.raises(ValueError):
        validate_runtime_auth_values(
            transport="streamable-http",
            auth_defaults=_auth_defaults(
                auth_mode="oauth2",
                oauth2_introspection_url="https://auth.example.com/introspect",
                oauth2_introspection_timeout_seconds=0.0,
            ),
        )

    validate_runtime_auth_values(
        transport="streamable-http",
        auth_defaults=_auth_defaults(
            auth_mode="oauth2",
            oauth2_introspection_url="https://auth.example.com/introspect",
            oauth2_client_id="client-id",
            oauth2_client_secret="client-secret",
            auth_required_scopes=("gcc.read",),
        ),
    )


def test_validate_runtime_security_policy_values_baseline_allows_local_defaults() -> None:
    validate_runtime_security_policy_values(
        transport="streamable-http",
        auth_mode="off",
        security_profile="baseline",
        audit_log_path="",
        audit_signing_key="",
    )


def test_validate_runtime_security_policy_values_signing_requires_audit_log() -> None:
    with pytest.raises(ValueError):
        validate_runtime_security_policy_values(
            transport="streamable-http",
            auth_mode="token",
            security_profile="baseline",
            audit_log_path="",
            audit_signing_key="signing-key",
        )


def test_validate_runtime_security_policy_values_signing_key_sources_mutually_exclusive() -> None:
    with pytest.raises(ValueError):
        validate_runtime_security_policy_values(
            transport="streamable-http",
            auth_mode="token",
            security_profile="baseline",
            audit_log_path=".GCC/audit.jsonl",
            audit_signing_key="signing-key",
            audit_signing_key_file=".secrets/audit-signing.key",
        )


def test_validate_runtime_security_policy_values_signing_key_id_requires_key_material() -> None:
    with pytest.raises(ValueError):
        validate_runtime_security_policy_values(
            transport="streamable-http",
            auth_mode="token",
            security_profile="baseline",
            audit_log_path=".GCC/audit.jsonl",
            audit_signing_key="",
            audit_signing_key_file="",
            audit_signing_key_id="key-a",
        )


def test_validate_runtime_security_policy_values_strict_mode() -> None:
    with pytest.raises(ValueError):
        validate_runtime_security_policy_values(
            transport="streamable-http",
            auth_mode="off",
            security_profile="strict",
            audit_log_path=".GCC/audit.jsonl",
            audit_signing_key="signing-key",
        )
    with pytest.raises(ValueError):
        validate_runtime_security_policy_values(
            transport="streamable-http",
            auth_mode="token",
            security_profile="strict",
            audit_log_path="",
            audit_signing_key="signing-key",
        )
    with pytest.raises(ValueError):
        validate_runtime_security_policy_values(
            transport="streamable-http",
            auth_mode="token",
            security_profile="strict",
            audit_log_path=".GCC/audit.jsonl",
            audit_signing_key="",
        )

    validate_runtime_security_policy_values(
        transport="streamable-http",
        auth_mode="token",
        security_profile="strict",
        audit_log_path=".GCC/audit.jsonl",
        audit_signing_key="signing-key",
    )
    validate_runtime_security_policy_values(
        transport="streamable-http",
        auth_mode="token",
        security_profile="strict",
        audit_log_path=".GCC/audit.jsonl",
        audit_signing_key="",
        audit_signing_key_file=".secrets/audit-signing.key",
    )
    with pytest.raises(ValueError):
        validate_runtime_security_policy_values(
            transport="streamable-http",
            auth_mode="token",
            security_profile="strict",
            audit_log_path=".GCC/audit.jsonl",
            audit_signing_key="signing-key",
            audit_signing_key_from_cli=True,
        )
    # Strict profile focuses on remote transport; stdio remains valid.
    validate_runtime_security_policy_values(
        transport="stdio",
        auth_mode="off",
        security_profile="strict",
        audit_log_path="",
        audit_signing_key="",
    )


def test_resolve_audit_signing_key_from_file(tmp_path) -> None:
    key_file = tmp_path / "audit-signing.key"
    key_file.write_text(" file-key-value \n", encoding="utf-8")
    assert (
        resolve_audit_signing_key(
            audit_signing_key="",
            audit_signing_key_file=str(key_file),
        )
        == "file-key-value"
    )


def test_resolve_audit_signing_key_rejects_invalid_file_state(tmp_path) -> None:
    with pytest.raises(ValueError):
        resolve_audit_signing_key(
            audit_signing_key="inline-key",
            audit_signing_key_file=str(tmp_path / "audit-signing.key"),
        )

    empty_file = tmp_path / "empty.key"
    empty_file.write_text("   \n", encoding="utf-8")
    with pytest.raises(ValueError):
        resolve_audit_signing_key(
            audit_signing_key="",
            audit_signing_key_file=str(empty_file),
        )

def test_resolve_auth_metadata_urls() -> None:
    issuer, resource = resolve_auth_metadata_urls(
        auth_defaults=_auth_defaults(auth_mode="token", auth_token="shared"),
        host="127.0.0.1",
        port=8000,
        streamable_http_path="/mcp",
    )
    assert issuer == "http://127.0.0.1:8000/mcp"
    assert resource == "http://127.0.0.1:8000/mcp"

    issuer, resource = resolve_auth_metadata_urls(
        auth_defaults=_auth_defaults(
            auth_mode="oauth2",
            oauth2_introspection_url="https://auth.example.com/introspect",
            auth_issuer_url="https://auth.example.com/",
            auth_resource_server_url="https://gcc.example.com/mcp",
        ),
        host="127.0.0.1",
        port=8000,
        streamable_http_path="/mcp",
    )
    assert issuer == "https://auth.example.com/"
    assert resource == "https://gcc.example.com/mcp"


def test_build_http_base_url_and_csv_parser() -> None:
    assert build_http_base_url("127.0.0.1", 8000, "/mcp") == "http://127.0.0.1:8000/mcp"
    assert build_http_base_url("::1", 8000, "mcp") == "http://[::1]:8000/mcp"
    assert parse_csv_values("a, b,,c") == ("a", "b", "c")
