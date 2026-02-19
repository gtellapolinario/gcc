"""Runtime configuration helpers."""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping

TRUE_VALUES = {"1", "true", "yes", "on"}
FALSE_VALUES = {"0", "false", "no", "off"}


def get_runtime_defaults(env: Mapping[str, str] | None = None) -> tuple[str, str, int]:
    """Validate and return runtime defaults from environment variables."""
    source = os.environ if env is None else env

    transport_default = source.get("GCC_MCP_TRANSPORT", "stdio")
    allowed_transports = {"stdio", "streamable-http"}
    if transport_default not in allowed_transports:
        raise ValueError("GCC_MCP_TRANSPORT must be 'stdio' or 'streamable-http'.")

    host_default = source.get("GCC_MCP_HOST", "127.0.0.1")

    port_env = source.get("GCC_MCP_PORT", "8000")
    try:
        port_default = int(port_env)
    except ValueError as exc:
        raise ValueError("GCC_MCP_PORT must be an integer.") from exc
    if not (1 <= port_default <= 65535):
        raise ValueError("GCC_MCP_PORT must be between 1 and 65535.")

    allow_public_http_default, _, _ = get_runtime_security_defaults(source)
    validate_streamable_http_binding(
        transport=transport_default,
        host=host_default,
        allow_public_http=allow_public_http_default,
    )

    return transport_default, host_default, port_default


def get_runtime_security_defaults(env: Mapping[str, str] | None = None) -> tuple[bool, str, bool]:
    """Return validated security/audit runtime settings from environment variables."""
    source = os.environ if env is None else env
    allow_public_http_default = _parse_bool_env(
        source=source,
        key="GCC_MCP_ALLOW_PUBLIC_HTTP",
        default=False,
    )
    audit_log_path = source.get("GCC_MCP_AUDIT_LOG", "").strip()
    audit_redact_sensitive = _parse_bool_env(
        source=source,
        key="GCC_MCP_AUDIT_REDACT",
        default=True,
    )
    return allow_public_http_default, audit_log_path, audit_redact_sensitive


def get_runtime_operations_defaults(env: Mapping[str, str] | None = None) -> tuple[int, int]:
    """Return validated operational guardrail settings from environment variables."""
    source = os.environ if env is None else env
    rate_limit_per_minute = _parse_int_env(
        source=source,
        key="GCC_MCP_RATE_LIMIT_PER_MINUTE",
        default=0,
        min_value=0,
    )
    audit_max_field_chars = _parse_int_env(
        source=source,
        key="GCC_MCP_AUDIT_MAX_FIELD_CHARS",
        default=4000,
        min_value=0,
    )
    validate_runtime_operation_values(
        rate_limit_per_minute=rate_limit_per_minute,
        audit_max_field_chars=audit_max_field_chars,
    )
    return rate_limit_per_minute, audit_max_field_chars


def validate_runtime_operation_values(rate_limit_per_minute: int, audit_max_field_chars: int) -> None:
    """Validate operation-level runtime values from CLI or other sources."""
    if rate_limit_per_minute < 0:
        raise ValueError("rate-limit-per-minute must be >= 0.")
    if audit_max_field_chars < 0 or (0 < audit_max_field_chars < 64):
        raise ValueError("audit-max-field-chars must be 0 or >= 64.")


def validate_streamable_http_binding(transport: str, host: str, allow_public_http: bool) -> None:
    """Validate host exposure policy for streamable HTTP transport."""
    if transport != "streamable-http":
        return
    if not host.strip():
        raise ValueError("Host must not be empty when using streamable-http transport.")
    if not is_loopback_host(host) and not allow_public_http:
        raise ValueError(
            "Refusing non-loopback streamable-http binding without explicit opt-in. "
            "Set --allow-public-http or GCC_MCP_ALLOW_PUBLIC_HTTP=true."
        )


def is_loopback_host(host: str) -> bool:
    """Return whether a host value maps to a loopback interface."""
    normalized = host.strip().lower().strip("[]")
    if normalized in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _parse_bool_env(source: Mapping[str, str], key: str, default: bool) -> bool:
    raw = source.get(key)
    if raw is None or not str(raw).strip():
        return default
    normalized = str(raw).strip().lower()
    if normalized in TRUE_VALUES:
        return True
    if normalized in FALSE_VALUES:
        return False
    raise ValueError(f"{key} must be a boolean value (true/false).")


def _parse_int_env(
    source: Mapping[str, str],
    key: str,
    default: int,
    min_value: int | None = None,
) -> int:
    raw = source.get(key)
    if raw is None or not str(raw).strip():
        return default
    try:
        parsed = int(str(raw).strip())
    except ValueError as exc:
        raise ValueError(f"{key} must be an integer.") from exc
    if min_value is not None and parsed < min_value:
        raise ValueError(f"{key} must be >= {min_value}.")
    return parsed
