"""Runtime configuration helpers."""

from __future__ import annotations

import ipaddress
import json
import math
import os
import re
from dataclasses import dataclass
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlparse

TRUE_VALUES = {"1", "true", "yes", "on"}
FALSE_VALUES = {"0", "false", "no", "off"}
AUTH_MODES = {"off", "token", "trusted-proxy-header", "oauth2"}
SECURITY_PROFILES = {"baseline", "strict"}
TRUSTED_PROXY_HEADER_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,127}$")


@dataclass(frozen=True)
class RuntimeAuthDefaults:
    """Runtime auth settings sourced from environment variables or CLI."""

    auth_mode: str
    auth_token: str
    trusted_proxy_header: str
    trusted_proxy_value: str
    oauth2_introspection_url: str
    oauth2_client_id: str
    oauth2_client_secret: str
    oauth2_introspection_timeout_seconds: float
    auth_issuer_url: str
    auth_resource_server_url: str
    auth_required_scopes: tuple[str, ...]


@dataclass(frozen=True)
class RuntimeSecurityPolicyDefaults:
    """Security-policy defaults sourced from environment variables or CLI."""

    security_profile: str
    audit_signing_key: str
    audit_signing_key_file: str
    audit_signing_key_id: str


@dataclass(frozen=True)
class RuntimePathResolutionDefaults:
    """Directory-resolution defaults for host/container path translation."""

    path_mappings: tuple[tuple[str, str], ...]
    allowed_roots: tuple[str, ...]


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


def get_runtime_security_policy_defaults(
    env: Mapping[str, str] | None = None,
) -> RuntimeSecurityPolicyDefaults:
    """Return security profile defaults from environment variables."""
    source = os.environ if env is None else env
    security_profile = source.get("GCC_MCP_SECURITY_PROFILE", "baseline").strip().lower()
    if security_profile not in SECURITY_PROFILES:
        allowed_profiles = ", ".join(sorted(SECURITY_PROFILES))
        raise ValueError(f"GCC_MCP_SECURITY_PROFILE must be one of: {allowed_profiles}.")
    return RuntimeSecurityPolicyDefaults(
        security_profile=security_profile,
        audit_signing_key=source.get("GCC_MCP_AUDIT_SIGNING_KEY", "").strip(),
        audit_signing_key_file=source.get("GCC_MCP_AUDIT_SIGNING_KEY_FILE", "").strip(),
        audit_signing_key_id=source.get("GCC_MCP_AUDIT_SIGNING_KEY_ID", "").strip(),
    )


def get_runtime_path_resolution_defaults(
    env: Mapping[str, str] | None = None,
) -> RuntimePathResolutionDefaults:
    """Return directory path-map/allowlist defaults from environment variables."""
    source = os.environ if env is None else env
    return RuntimePathResolutionDefaults(
        path_mappings=_parse_path_map_env(source=source, key="GCC_MCP_PATH_MAP"),
        allowed_roots=_parse_path_list_env(source=source, key="GCC_MCP_ALLOWED_ROOTS"),
    )


def get_runtime_auth_defaults(env: Mapping[str, str] | None = None) -> RuntimeAuthDefaults:
    """Return auth defaults from environment variables with type parsing."""
    source = os.environ if env is None else env
    auth_mode = source.get("GCC_MCP_AUTH_MODE", "off").strip().lower()
    if auth_mode not in AUTH_MODES:
        allowed_modes = ", ".join(sorted(AUTH_MODES))
        raise ValueError(f"GCC_MCP_AUTH_MODE must be one of: {allowed_modes}.")

    timeout_seconds = _parse_float_env(
        source=source,
        key="GCC_MCP_OAUTH2_INTROSPECTION_TIMEOUT_SECONDS",
        default=5.0,
        min_value=0.1,
    )

    return RuntimeAuthDefaults(
        auth_mode=auth_mode,
        auth_token=source.get("GCC_MCP_AUTH_TOKEN", "").strip(),
        trusted_proxy_header=source.get("GCC_MCP_TRUSTED_PROXY_HEADER", "").strip(),
        trusted_proxy_value=source.get("GCC_MCP_TRUSTED_PROXY_VALUE", "").strip(),
        oauth2_introspection_url=source.get("GCC_MCP_OAUTH2_INTROSPECTION_URL", "").strip(),
        oauth2_client_id=source.get("GCC_MCP_OAUTH2_CLIENT_ID", "").strip(),
        oauth2_client_secret=source.get("GCC_MCP_OAUTH2_CLIENT_SECRET", "").strip(),
        oauth2_introspection_timeout_seconds=timeout_seconds,
        auth_issuer_url=source.get("GCC_MCP_AUTH_ISSUER_URL", "").strip(),
        auth_resource_server_url=source.get("GCC_MCP_AUTH_RESOURCE_SERVER_URL", "").strip(),
        auth_required_scopes=parse_csv_values(source.get("GCC_MCP_AUTH_REQUIRED_SCOPES", "")),
    )


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


def validate_runtime_auth_values(
    transport: str,
    auth_defaults: RuntimeAuthDefaults,
) -> None:
    """Validate runtime auth options after CLI+env merging."""
    auth_mode = auth_defaults.auth_mode
    if auth_mode not in AUTH_MODES:
        allowed_modes = ", ".join(sorted(AUTH_MODES))
        raise ValueError(f"auth-mode must be one of: {allowed_modes}.")

    if auth_mode != "off" and transport != "streamable-http":
        raise ValueError("auth-mode requires --transport streamable-http.")

    if auth_mode == "off":
        return

    if auth_defaults.auth_issuer_url:
        _validate_http_url(auth_defaults.auth_issuer_url, field_name="auth-issuer-url")
    if auth_defaults.auth_resource_server_url:
        _validate_http_url(
            auth_defaults.auth_resource_server_url,
            field_name="auth-resource-server-url",
        )

    if auth_mode == "token":
        if not auth_defaults.auth_token.strip():
            raise ValueError("auth-token must be set when auth-mode=token.")
        return

    if auth_mode == "trusted-proxy-header":
        if not auth_defaults.trusted_proxy_header:
            raise ValueError(
                "trusted-proxy-header must be set when auth-mode=trusted-proxy-header."
            )
        if not TRUSTED_PROXY_HEADER_PATTERN.fullmatch(auth_defaults.trusted_proxy_header):
            raise ValueError(
                "trusted-proxy-header contains invalid characters. "
                "Use letters, numbers, and hyphens only."
            )
        if not auth_defaults.trusted_proxy_value.strip():
            raise ValueError("trusted-proxy-value must be set when auth-mode=trusted-proxy-header.")
        return

    if not auth_defaults.oauth2_introspection_url:
        raise ValueError("oauth2-introspection-url must be set when auth-mode=oauth2.")
    _validate_http_url(
        auth_defaults.oauth2_introspection_url,
        field_name="oauth2-introspection-url",
    )
    if auth_defaults.oauth2_introspection_timeout_seconds <= 0:
        raise ValueError("oauth2-introspection-timeout-seconds must be > 0.")
    has_client_id = bool(auth_defaults.oauth2_client_id)
    has_client_secret = bool(auth_defaults.oauth2_client_secret)
    if has_client_id != has_client_secret:
        raise ValueError(
            "oauth2-client-id and oauth2-client-secret must be provided together."
        )


def validate_runtime_security_policy_values(
    transport: str,
    auth_mode: str,
    security_profile: str,
    audit_log_path: str,
    audit_signing_key: str,
    audit_signing_key_file: str = "",
    audit_signing_key_id: str = "",
    audit_signing_key_from_cli: bool = False,
) -> None:
    """Validate security policy interactions for remote runtime hardening."""
    if security_profile not in SECURITY_PROFILES:
        allowed_profiles = ", ".join(sorted(SECURITY_PROFILES))
        raise ValueError(f"security-profile must be one of: {allowed_profiles}.")

    normalized_audit_log_path = audit_log_path.strip()
    normalized_signing_key = audit_signing_key.strip()
    normalized_signing_key_file = audit_signing_key_file.strip()
    normalized_signing_key_id = audit_signing_key_id.strip()

    if normalized_signing_key and normalized_signing_key_file:
        raise ValueError("audit-signing-key and audit-signing-key-file are mutually exclusive.")
    if normalized_signing_key_id and not (normalized_signing_key or normalized_signing_key_file):
        raise ValueError("audit-signing-key-id requires audit-signing-key material.")

    if (normalized_signing_key or normalized_signing_key_file) and not normalized_audit_log_path:
        raise ValueError("audit-signing-key requires audit-log-file.")

    if security_profile != "strict" or transport != "streamable-http":
        return

    if audit_signing_key_from_cli and normalized_signing_key:
        raise ValueError(
            "security-profile strict forbids --audit-signing-key. "
            "Use GCC_MCP_AUDIT_SIGNING_KEY or --audit-signing-key-file."
        )

    if auth_mode == "off":
        raise ValueError(
            "security-profile strict requires auth-mode other than 'off' for streamable-http."
        )
    if not normalized_audit_log_path:
        raise ValueError(
            "security-profile strict requires audit-log-file for streamable-http."
        )
    if not (normalized_signing_key or normalized_signing_key_file):
        raise ValueError(
            "security-profile strict requires audit-signing-key for streamable-http."
        )


def resolve_audit_signing_key(audit_signing_key: str, audit_signing_key_file: str) -> str:
    """Resolve audit signing key from direct value or file source."""
    normalized_signing_key = audit_signing_key.strip()
    normalized_signing_key_file = audit_signing_key_file.strip()

    if normalized_signing_key and normalized_signing_key_file:
        raise ValueError("audit-signing-key and audit-signing-key-file are mutually exclusive.")
    if not normalized_signing_key_file:
        return normalized_signing_key

    key_path = Path(normalized_signing_key_file).expanduser()
    try:
        signing_key_from_file = key_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ValueError("Unable to read audit-signing-key-file.") from exc
    if not signing_key_from_file:
        raise ValueError("audit-signing-key-file must contain a non-empty key.")
    return signing_key_from_file


def resolve_auth_metadata_urls(
    auth_defaults: RuntimeAuthDefaults,
    host: str,
    port: int,
    streamable_http_path: str,
) -> tuple[str, str]:
    """Resolve auth metadata URLs, deriving safe defaults when omitted."""
    resource_server_url = auth_defaults.auth_resource_server_url or build_http_base_url(
        host=host,
        port=port,
        path=streamable_http_path,
    )
    issuer_url = auth_defaults.auth_issuer_url or resource_server_url
    _validate_http_url(issuer_url, field_name="auth-issuer-url")
    _validate_http_url(resource_server_url, field_name="auth-resource-server-url")
    return issuer_url, resource_server_url


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


def parse_csv_values(value: str | None) -> tuple[str, ...]:
    """Parse comma-separated values into a normalized tuple."""
    if not value:
        return ()
    return tuple(part.strip() for part in value.split(",") if part.strip())


def build_http_base_url(host: str, port: int, path: str) -> str:
    """Build an HTTP URL from host/port/path, handling IPv6 host formatting."""
    normalized_host = host.strip()
    if ":" in normalized_host and not normalized_host.startswith("["):
        normalized_host = f"[{normalized_host}]"

    normalized_path = path.strip() or "/"
    if not normalized_path.startswith("/"):
        normalized_path = f"/{normalized_path}"

    return f"http://{normalized_host}:{port}{normalized_path}"


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


def _parse_float_env(
    source: Mapping[str, str],
    key: str,
    default: float,
    min_value: float | None = None,
) -> float:
    raw = source.get(key)
    if raw is None or not str(raw).strip():
        return default
    try:
        parsed = float(str(raw).strip())
    except ValueError as exc:
        raise ValueError(f"{key} must be a number.") from exc
    if not math.isfinite(parsed):
        raise ValueError(f"{key} must be a finite number.")
    if min_value is not None and parsed < min_value:
        raise ValueError(f"{key} must be >= {min_value}.")
    return parsed


def _parse_path_map_env(source: Mapping[str, str], key: str) -> tuple[tuple[str, str], ...]:
    raw = source.get(key)
    if raw is None or not str(raw).strip():
        return ()

    try:
        payload = json.loads(str(raw).strip())
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"{key} must be valid JSON (object or list of {{\"from\":..., \"to\":...}} mappings)."
        ) from exc

    candidate_pairs: list[tuple[str, str]] = []
    if isinstance(payload, dict):
        for source_path, target_path in payload.items():
            if not isinstance(source_path, str) or not isinstance(target_path, str):
                raise ValueError(f"{key} object mapping entries must use string paths.")
            candidate_pairs.append((source_path, target_path))
    elif isinstance(payload, list):
        for index, item in enumerate(payload):
            if not isinstance(item, Mapping):
                raise ValueError(f"{key}[{index}] must be an object with 'from' and 'to' fields.")
            source_path = item.get("from")
            target_path = item.get("to")
            if not isinstance(source_path, str) or not isinstance(target_path, str):
                raise ValueError(
                    f"{key}[{index}] must contain string 'from' and 'to' values."
                )
            candidate_pairs.append((source_path, target_path))
    else:
        raise ValueError(
            f"{key} must be a JSON object or a list of {{\"from\":..., \"to\":...}} entries."
        )

    normalized: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for source_path, target_path in candidate_pairs:
        normalized_source = _normalize_absolute_path_value(
            value=source_path,
            key=key,
            path_label="from",
        )
        normalized_target = _normalize_absolute_path_value(
            value=target_path,
            key=key,
            path_label="to",
        )
        pair = (normalized_source, normalized_target)
        if pair in seen:
            continue
        seen.add(pair)
        normalized.append(pair)

    return tuple(normalized)


def _parse_path_list_env(source: Mapping[str, str], key: str) -> tuple[str, ...]:
    raw = source.get(key)
    if raw is None or not str(raw).strip():
        return ()

    value = str(raw).strip()
    parsed_values: list[str]
    if value.startswith("["):
        try:
            payload = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"{key} must be a comma-separated list of absolute paths or a JSON list."
            ) from exc
        if not isinstance(payload, list):
            raise ValueError(f"{key} JSON form must be a list of absolute paths.")
        if not all(isinstance(item, str) for item in payload):
            raise ValueError(f"{key} JSON list entries must be strings.")
        parsed_values = [str(item) for item in payload]
    else:
        parsed_values = [part for part in value.split(",") if part.strip()]

    normalized: list[str] = []
    seen: set[str] = set()
    for item in parsed_values:
        normalized_item = _normalize_absolute_path_value(
            value=item,
            key=key,
            path_label="entry",
        )
        if normalized_item in seen:
            continue
        seen.add(normalized_item)
        normalized.append(normalized_item)
    return tuple(normalized)


def _normalize_absolute_path_value(value: str, key: str, path_label: str) -> str:
    normalized = str(value).strip()
    if not normalized:
        raise ValueError(f"{key} {path_label} path must be non-empty.")

    path = Path(normalized).expanduser()
    if not path.is_absolute():
        raise ValueError(f"{key} {path_label} path must be absolute: {normalized}")
    return str(path.resolve(strict=False))


def _validate_http_url(value: str, field_name: str) -> None:
    parsed = urlparse(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"{field_name} must be a valid http(s) URL.")
