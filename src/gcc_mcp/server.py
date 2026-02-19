"""MCP server entrypoint and tool definitions for GCC."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Annotated, Any, Callable

from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from pydantic import Field, ValidationError

from .auth import (
    OAuth2IntrospectionTokenVerifier,
    StaticTokenVerifier,
    TrustedProxyHeaderMiddleware,
)
from .audit import AuditLogger
from .engine import GCCEngine
from .errors import ErrorCode, GCCError
from .limits import RateLimiter
from .models import (
    BranchRequest,
    CommitRequest,
    ContextRequest,
    InitRequest,
    MergeRequest,
    StatusRequest,
)
from .runtime import (
    AUTH_MODES,
    RuntimeAuthDefaults,
    RuntimeSecurityPolicyDefaults,
    SECURITY_PROFILES,
    get_runtime_defaults,
    get_runtime_auth_defaults,
    get_runtime_operations_defaults,
    get_runtime_security_policy_defaults,
    parse_csv_values,
    resolve_audit_signing_key,
    resolve_auth_metadata_urls,
    get_runtime_security_defaults,
    validate_runtime_auth_values,
    validate_runtime_security_policy_values,
    validate_runtime_operation_values,
    validate_streamable_http_binding,
)

logger = logging.getLogger(__name__)

mcp = FastMCP(
    name="git-context-controller",
    instructions=(
        "Manage AI agent project context with Git-inspired operations. "
        "Use gcc_init, gcc_commit, gcc_branch, gcc_merge, gcc_context, and gcc_status "
        "to checkpoint work, explore alternatives, and recover structured history."
    ),
    version="0.1.0",
    json_response=True,
)

engine = GCCEngine()
audit_logger = AuditLogger()
rate_limiter = RateLimiter()

READ_ONLY_TOOL_ANNOTATIONS = {
    "readOnlyHint": True,
    "idempotentHint": True,
    "destructiveHint": False,
    "openWorldHint": False,
}

WRITE_TOOL_ANNOTATIONS = {
    "readOnlyHint": False,
    "idempotentHint": False,
    "destructiveHint": False,
    "openWorldHint": False,
}


def _register_tool(annotations: dict[str, bool]):
    """Register tool with annotations, with backwards-compatible fallback."""

    def decorator(func):
        try:
            return mcp.tool(annotations=annotations)(func)
        except TypeError as exc:
            message = str(exc).lower()
            if "annotations" in message or "unexpected keyword argument" in message:
                logger.debug(
                    "FastMCP tool annotations not supported in this SDK version; using fallback."
                )
                return mcp.tool()(func)
            raise

    return decorator


def _error_payload_from_exception(exc: Exception) -> dict[str, Any]:
    """Convert internal exceptions into stable MCP error payloads."""
    if isinstance(exc, GCCError):
        payload = exc.to_payload()
    elif isinstance(exc, ValidationError):
        errors: Any
        try:
            errors = exc.errors(include_context=False, include_input=False)
        except TypeError:
            errors = exc.errors()
        payload = {
            "status": "error",
            "error_code": ErrorCode.INVALID_INPUT.value,
            "message": "Input validation failed",
            "suggestion": "Check field constraints and request schema.",
            "details": {"errors": errors},
        }
    else:
        logger.exception("Unhandled server exception", exc_info=exc)
        payload = {
            "status": "error",
            "error_code": ErrorCode.INTERNAL_ERROR.value,
            "message": str(exc),
            "suggestion": "Check server logs and retry the operation.",
            "details": {},
        }
    return payload


def _run_tool(
    tool_name: str,
    request_payload: dict[str, Any],
    operation: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    """Execute tool operation and emit structured audit event."""
    allowed, retry_after_seconds = rate_limiter.allow()
    if not allowed:
        error_payload = GCCError(
            ErrorCode.RATE_LIMITED,
            f"Rate limit exceeded for tool '{tool_name}'",
            "Retry later or increase rate-limit-per-minute.",
            {"retry_after_seconds": retry_after_seconds},
        ).to_payload()
        audit_logger.log_tool_event(
            tool_name=tool_name,
            status="error",
            request_payload=request_payload,
            response_payload=error_payload,
        )
        return error_payload

    try:
        response_payload = operation()
        audit_logger.log_tool_event(
            tool_name=tool_name,
            status="success",
            request_payload=request_payload,
            response_payload=response_payload,
        )
        return response_payload
    except Exception as exc:  # noqa: BLE001
        error_payload = _error_payload_from_exception(exc)
        audit_logger.log_tool_event(
            tool_name=tool_name,
            status="error",
            request_payload=request_payload,
            response_payload=error_payload,
        )
        return error_payload


@_register_tool(WRITE_TOOL_ANNOTATIONS)
def gcc_init(
    directory: Annotated[
        str, Field(description="Path to directory where .GCC should be initialized")
    ],
    project_name: Annotated[
        str, Field(min_length=1, max_length=100, description="Name of the project")
    ],
    project_description: Annotated[
        str, Field(max_length=500, description="Brief project description")
    ] = "",
    initial_goals: Annotated[
        list[str] | None, Field(description="Initial goals for the project", max_length=20)
    ] = None,
    git_context_policy: Annotated[
        str,
        Field(
            description=(
                "Git tracking policy for .GCC: "
                "'ignore' adds .GCC/ to .gitignore (default), "
                "'track' keeps .GCC tracked. "
                "If 'track', acknowledge_sensitive_data_risk must be true."
            )
        ),
    ] = "ignore",
    acknowledge_sensitive_data_risk: Annotated[
        bool,
        Field(
            description=(
                "Required when git_context_policy='track'. "
                "Confirms informed consent that .GCC may contain sensitive context."
            )
        ),
    ] = False,
) -> dict[str, Any]:
    """Initialize GCC structure in a directory."""
    request_payload = {
        "directory": directory,
        "project_name": project_name,
        "project_description": project_description,
        "initial_goals": initial_goals or [],
        "git_context_policy": git_context_policy,
        "acknowledge_sensitive_data_risk": acknowledge_sensitive_data_risk,
    }

    def _operation() -> dict[str, Any]:
        request = InitRequest(
            directory=directory,
            project_name=project_name,
            project_description=project_description,
            initial_goals=initial_goals or [],
            git_context_policy=git_context_policy,
            acknowledge_sensitive_data_risk=acknowledge_sensitive_data_risk,
        )
        return engine.initialize(request).model_dump(mode="json")

    return _run_tool("gcc_init", request_payload=request_payload, operation=_operation)


@_register_tool(WRITE_TOOL_ANNOTATIONS)
def gcc_commit(
    directory: Annotated[str, Field(description="Path to GCC-enabled directory")],
    message: Annotated[str, Field(min_length=1, max_length=200, description="Commit message")],
    commit_type: Annotated[
        str,
        Field(
            description="Commit type: feature, bugfix, refactor, test, docs, or chore",
        ),
    ] = "feature",
    details: Annotated[
        list[str] | None,
        Field(description="Key achievements completed in this checkpoint"),
    ] = None,
    files_modified: Annotated[
        list[str] | None,
        Field(description="Files modified for this checkpoint"),
    ] = None,
    tests_passed: Annotated[bool, Field(description="Whether tests passed")] = True,
    notes: Annotated[str, Field(description="Additional notes for the checkpoint")] = "",
    tags: Annotated[list[str] | None, Field(description="Tags for categorization")] = None,
    ota_log: Annotated[
        dict[str, str] | None,
        Field(description="Observation-Thought-Action-Result details"),
    ] = None,
) -> dict[str, Any]:
    """Checkpoint meaningful progress and store milestone details."""
    request_payload = {
        "directory": directory,
        "message": message,
        "commit_type": commit_type,
        "details": details or [],
        "files_modified": files_modified or [],
        "tests_passed": tests_passed,
        "notes": notes,
        "tags": tags or [],
        "ota_log": ota_log,
    }

    def _operation() -> dict[str, Any]:
        request = CommitRequest(
            directory=directory,
            message=message,
            commit_type=commit_type,
            details=details or [],
            files_modified=files_modified or [],
            tests_passed=tests_passed,
            notes=notes,
            tags=tags or [],
            ota_log=ota_log,
        )
        return engine.commit(request).model_dump(mode="json")

    return _run_tool("gcc_commit", request_payload=request_payload, operation=_operation)


@_register_tool(WRITE_TOOL_ANNOTATIONS)
def gcc_branch(
    directory: Annotated[str, Field(description="Path to GCC-enabled directory")],
    name: Annotated[
        str,
        Field(
            min_length=1,
            max_length=50,
            pattern=r"^[a-z0-9-]+$",
            description="Branch name (lowercase letters, numbers, hyphens)",
        ),
    ],
    description: Annotated[str, Field(min_length=1, max_length=200, description="Branch purpose")],
    from_branch: Annotated[str, Field(description="Parent branch")] = "main",
    copy_context: Annotated[bool, Field(description="Copy parent branch context")] = True,
    tags: Annotated[list[str] | None, Field(description="Tags for branch categorization")] = None,
) -> dict[str, Any]:
    """Create a branch to explore an alternative strategy."""
    request_payload = {
        "directory": directory,
        "name": name,
        "description": description,
        "from_branch": from_branch,
        "copy_context": copy_context,
        "tags": tags or [],
    }

    def _operation() -> dict[str, Any]:
        request = BranchRequest(
            directory=directory,
            name=name,
            description=description,
            from_branch=from_branch,
            copy_context=copy_context,
            tags=tags or [],
        )
        return engine.branch(request).model_dump(mode="json")

    return _run_tool("gcc_branch", request_payload=request_payload, operation=_operation)


@_register_tool(WRITE_TOOL_ANNOTATIONS)
def gcc_merge(
    directory: Annotated[str, Field(description="Path to GCC-enabled directory")],
    source_branch: Annotated[str, Field(description="Branch to merge from")],
    summary: Annotated[str, Field(min_length=1, max_length=500, description="Merge summary")],
    target_branch: Annotated[str, Field(description="Branch to merge into")] = "main",
    keep_branch: Annotated[bool, Field(description="Keep source branch after merge")] = False,
    update_roadmap: Annotated[bool, Field(description="Update roadmap notes in main.md")] = True,
) -> dict[str, Any]:
    """Merge a completed branch into a target branch."""
    request_payload = {
        "directory": directory,
        "source_branch": source_branch,
        "target_branch": target_branch,
        "summary": summary,
        "keep_branch": keep_branch,
        "update_roadmap": update_roadmap,
    }

    def _operation() -> dict[str, Any]:
        request = MergeRequest(
            directory=directory,
            source_branch=source_branch,
            target_branch=target_branch,
            summary=summary,
            keep_branch=keep_branch,
            update_roadmap=update_roadmap,
        )
        return engine.merge(request).model_dump(mode="json")

    return _run_tool("gcc_merge", request_payload=request_payload, operation=_operation)


@_register_tool(READ_ONLY_TOOL_ANNOTATIONS)
def gcc_context(
    directory: Annotated[str, Field(description="Path to GCC-enabled directory")],
    level: Annotated[
        str,
        Field(description="Context detail level: summary, detailed, or full"),
    ] = "summary",
    scope: Annotated[
        list[str] | None,
        Field(description="Branch names to include in context output"),
    ] = None,
    since: Annotated[
        str | None,
        Field(description="ISO date filter (YYYY-MM-DD) for history entries"),
    ] = None,
    tags: Annotated[
        list[str] | None,
        Field(description="Tags to filter history entries"),
    ] = None,
    format: Annotated[
        str,
        Field(description="Output format: markdown, json, yaml"),
    ] = "markdown",
    redact_sensitive: Annotated[
        bool,
        Field(description="Apply conservative redaction to potentially sensitive fields."),
    ] = False,
) -> dict[str, Any]:
    """Retrieve context snapshots across branches."""
    request_payload = {
        "directory": directory,
        "level": level,
        "scope": scope or [],
        "since": since,
        "tags": tags or [],
        "format": format,
        "redact_sensitive": redact_sensitive,
    }

    def _operation() -> dict[str, Any]:
        request = ContextRequest(
            directory=directory,
            level=level,
            scope=scope or [],
            since=since,
            tags=tags or [],
            format=format,
            redact_sensitive=redact_sensitive,
        )
        return engine.get_context(request).model_dump(mode="json")

    return _run_tool("gcc_context", request_payload=request_payload, operation=_operation)


@_register_tool(READ_ONLY_TOOL_ANNOTATIONS)
def gcc_status(
    directory: Annotated[str, Field(description="Path to GCC-enabled directory")],
) -> dict[str, Any]:
    """Get a quick status summary for a GCC project."""
    request_payload = {"directory": directory}

    def _operation() -> dict[str, Any]:
        request = StatusRequest(directory=directory)
        return engine.get_status(request).model_dump(mode="json")

    return _run_tool("gcc_status", request_payload=request_payload, operation=_operation)


def _configure_fastmcp_auth(auth_defaults: RuntimeAuthDefaults, host: str, port: int) -> None:
    """Apply auth settings to the global FastMCP instance."""
    mcp.settings.host = host
    mcp.settings.port = port

    if auth_defaults.auth_mode == "off":
        mcp.settings.auth = None
        setattr(mcp, "_token_verifier", None)
        return

    if auth_defaults.auth_mode == "trusted-proxy-header":
        mcp.settings.auth = None
        setattr(mcp, "_token_verifier", None)
        return

    issuer_url, resource_server_url = resolve_auth_metadata_urls(
        auth_defaults=auth_defaults,
        host=host,
        port=port,
        streamable_http_path=mcp.settings.streamable_http_path,
    )
    mcp.settings.auth = AuthSettings(
        issuer_url=issuer_url,
        resource_server_url=resource_server_url,
        required_scopes=list(auth_defaults.auth_required_scopes) or None,
    )

    if auth_defaults.auth_mode == "token":
        token_verifier = StaticTokenVerifier(
            expected_token=auth_defaults.auth_token,
            scopes=list(auth_defaults.auth_required_scopes),
        )
    else:
        token_verifier = OAuth2IntrospectionTokenVerifier(
            introspection_url=auth_defaults.oauth2_introspection_url,
            timeout_seconds=auth_defaults.oauth2_introspection_timeout_seconds,
            client_id=auth_defaults.oauth2_client_id,
            client_secret=auth_defaults.oauth2_client_secret,
            required_scopes=list(auth_defaults.auth_required_scopes),
        )

    setattr(mcp, "_token_verifier", token_verifier)


def _run_streamable_http_with_proxy_header_auth(
    header_name: str,
    header_value: str,
) -> None:
    """Run streamable HTTP with trusted-proxy header validation middleware."""
    import uvicorn

    wrapped_app = TrustedProxyHeaderMiddleware(
        app=mcp.streamable_http_app(),
        header_name=header_name,
        expected_value=header_value,
    )
    config = uvicorn.Config(
        wrapped_app,
        host=mcp.settings.host,
        port=mcp.settings.port,
        log_level=mcp.settings.log_level.lower(),
    )
    uvicorn.Server(config).run()


def _cli_option_supplied(option_name: str) -> bool:
    """Return whether a CLI option was explicitly provided."""
    return any(
        argument == option_name or argument.startswith(f"{option_name}=")
        for argument in sys.argv[1:]
    )


def main() -> None:
    """Run GCC MCP server in stdio or streamable HTTP mode."""
    parser = argparse.ArgumentParser(description="GCC MCP server")
    try:
        transport_default, host_default, port_default = get_runtime_defaults()
        (
            allow_public_http_default,
            audit_log_path_default,
            audit_redact_default,
        ) = get_runtime_security_defaults()
        security_policy_defaults = get_runtime_security_policy_defaults()
        rate_limit_default, audit_max_field_chars_default = get_runtime_operations_defaults()
        auth_defaults = get_runtime_auth_defaults()
    except ValueError as exc:
        parser.error(str(exc))
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http"],
        default=transport_default,
        help="Server transport mode (default: stdio).",
    )
    parser.add_argument(
        "--host",
        default=host_default,
        help="Host for streamable HTTP transport.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=port_default,
        help="Port for streamable HTTP transport.",
    )
    parser.add_argument(
        "--allow-public-http",
        action=argparse.BooleanOptionalAction,
        default=allow_public_http_default,
        help=(
            "Allow non-loopback streamable-http host binding. "
            "Required for 0.0.0.0 or other public interface hosts."
        ),
    )
    parser.add_argument(
        "--audit-log-file",
        default=audit_log_path_default,
        help="Optional JSONL audit log path for MCP tool calls.",
    )
    parser.add_argument(
        "--audit-redact-sensitive",
        action=argparse.BooleanOptionalAction,
        default=audit_redact_default,
        help="Redact sensitive-looking fields in audit logs (default: enabled).",
    )
    parser.add_argument(
        "--rate-limit-per-minute",
        type=int,
        default=rate_limit_default,
        help="Max MCP tool calls per minute (0 disables limiter).",
    )
    parser.add_argument(
        "--audit-max-field-chars",
        type=int,
        default=audit_max_field_chars_default,
        help="Max characters for each string field written to audit logs.",
    )
    parser.add_argument(
        "--security-profile",
        choices=sorted(SECURITY_PROFILES),
        default=security_policy_defaults.security_profile,
        help=(
            "Runtime security profile: baseline (default) or strict "
            "(enforces stronger streamable-http controls)."
        ),
    )
    parser.add_argument(
        "--audit-signing-key",
        default=security_policy_defaults.audit_signing_key,
        help=(
            "Optional key for HMAC-signed audit events. "
            "Prefer GCC_MCP_AUDIT_SIGNING_KEY environment variable for secrets."
        ),
    )
    parser.add_argument(
        "--audit-signing-key-file",
        default=security_policy_defaults.audit_signing_key_file,
        help=(
            "Optional file containing HMAC key for signed audit events. "
            "Recommended for strict profile deployments."
        ),
    )
    parser.add_argument(
        "--audit-signing-key-id",
        default=security_policy_defaults.audit_signing_key_id,
        help="Optional key identifier persisted with signed audit events for rotation support.",
    )
    parser.add_argument(
        "--auth-mode",
        choices=sorted(AUTH_MODES),
        default=auth_defaults.auth_mode,
        help=(
            "Authentication mode for streamable HTTP: "
            "off, token, trusted-proxy-header, oauth2."
        ),
    )
    parser.add_argument(
        "--auth-token",
        default=auth_defaults.auth_token,
        help=(
            "Static bearer token for auth-mode=token. "
            "Prefer GCC_MCP_AUTH_TOKEN environment variable for secrets."
        ),
    )
    parser.add_argument(
        "--trusted-proxy-header",
        default=auth_defaults.trusted_proxy_header,
        help="Header name required when auth-mode=trusted-proxy-header.",
    )
    parser.add_argument(
        "--trusted-proxy-value",
        default=auth_defaults.trusted_proxy_value,
        help=(
            "Expected trusted proxy header value for auth-mode=trusted-proxy-header. "
            "Prefer GCC_MCP_TRUSTED_PROXY_VALUE environment variable."
        ),
    )
    parser.add_argument(
        "--oauth2-introspection-url",
        default=auth_defaults.oauth2_introspection_url,
        help="OAuth2 token introspection endpoint for auth-mode=oauth2.",
    )
    parser.add_argument(
        "--oauth2-client-id",
        default=auth_defaults.oauth2_client_id,
        help="Client ID used for OAuth2 token introspection auth (optional).",
    )
    parser.add_argument(
        "--oauth2-client-secret",
        default=auth_defaults.oauth2_client_secret,
        help=(
            "Client secret used for OAuth2 introspection auth (optional). "
            "Prefer GCC_MCP_OAUTH2_CLIENT_SECRET environment variable."
        ),
    )
    parser.add_argument(
        "--oauth2-introspection-timeout-seconds",
        type=float,
        default=auth_defaults.oauth2_introspection_timeout_seconds,
        help="Timeout in seconds for OAuth2 introspection requests.",
    )
    parser.add_argument(
        "--auth-issuer-url",
        default=auth_defaults.auth_issuer_url,
        help="Issuer URL advertised in MCP auth metadata (optional).",
    )
    parser.add_argument(
        "--auth-resource-server-url",
        default=auth_defaults.auth_resource_server_url,
        help="Resource server URL advertised in MCP auth metadata (optional).",
    )
    parser.add_argument(
        "--auth-required-scopes",
        default=",".join(auth_defaults.auth_required_scopes),
        help="Comma-separated required OAuth scopes for streamable HTTP auth.",
    )
    args = parser.parse_args()
    runtime_policy = RuntimeSecurityPolicyDefaults(
        security_profile=str(args.security_profile).strip().lower(),
        audit_signing_key=str(args.audit_signing_key).strip(),
        audit_signing_key_file=str(args.audit_signing_key_file).strip(),
        audit_signing_key_id=str(args.audit_signing_key_id).strip(),
    )
    runtime_auth = RuntimeAuthDefaults(
        auth_mode=args.auth_mode,
        auth_token=str(args.auth_token).strip(),
        trusted_proxy_header=str(args.trusted_proxy_header).strip(),
        trusted_proxy_value=str(args.trusted_proxy_value).strip(),
        oauth2_introspection_url=str(args.oauth2_introspection_url).strip(),
        oauth2_client_id=str(args.oauth2_client_id).strip(),
        oauth2_client_secret=str(args.oauth2_client_secret).strip(),
        oauth2_introspection_timeout_seconds=float(args.oauth2_introspection_timeout_seconds),
        auth_issuer_url=str(args.auth_issuer_url).strip(),
        auth_resource_server_url=str(args.auth_resource_server_url).strip(),
        auth_required_scopes=parse_csv_values(args.auth_required_scopes),
    )

    try:
        validate_streamable_http_binding(
            transport=args.transport,
            host=args.host,
            allow_public_http=args.allow_public_http,
        )
        validate_runtime_operation_values(
            rate_limit_per_minute=args.rate_limit_per_minute,
            audit_max_field_chars=args.audit_max_field_chars,
        )
        validate_runtime_auth_values(
            transport=args.transport,
            auth_defaults=runtime_auth,
        )
        validate_runtime_security_policy_values(
            transport=args.transport,
            auth_mode=runtime_auth.auth_mode,
            security_profile=runtime_policy.security_profile,
            audit_log_path=str(args.audit_log_file),
            audit_signing_key=runtime_policy.audit_signing_key,
            audit_signing_key_file=runtime_policy.audit_signing_key_file,
            audit_signing_key_id=runtime_policy.audit_signing_key_id,
            audit_signing_key_from_cli=(
                _cli_option_supplied("--audit-signing-key")
                and bool(runtime_policy.audit_signing_key)
            ),
        )
        resolved_audit_signing_key = resolve_audit_signing_key(
            audit_signing_key=runtime_policy.audit_signing_key,
            audit_signing_key_file=runtime_policy.audit_signing_key_file,
        )
    except ValueError as exc:
        parser.error(str(exc))

    global audit_logger
    global rate_limiter
    audit_path = str(args.audit_log_file).strip()
    audit_logger = AuditLogger(
        log_path=Path(audit_path) if audit_path else None,
        redact_sensitive=bool(args.audit_redact_sensitive),
        max_field_chars=int(args.audit_max_field_chars),
        signing_key=resolved_audit_signing_key,
        signing_key_id=runtime_policy.audit_signing_key_id,
    )
    rate_limiter.configure(int(args.rate_limit_per_minute))
    _configure_fastmcp_auth(
        auth_defaults=runtime_auth,
        host=args.host,
        port=int(args.port),
    )

    if args.transport == "stdio":
        mcp.run()
        return

    if runtime_auth.auth_mode == "trusted-proxy-header":
        _run_streamable_http_with_proxy_header_auth(
            header_name=runtime_auth.trusted_proxy_header,
            header_value=runtime_auth.trusted_proxy_value,
        )
        return

    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
