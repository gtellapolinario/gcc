"""MCP server entrypoint and tool definitions for GCC."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
import types
import uuid
from datetime import date
from pathlib import Path
from typing import Annotated, Any, Callable, Union, get_args, get_origin, get_type_hints

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
    RuntimePathResolutionDefaults,
    RuntimeSecurityPolicyDefaults,
    SECURITY_PROFILES,
    get_runtime_defaults,
    get_runtime_auth_defaults,
    get_runtime_operations_defaults,
    get_runtime_path_resolution_defaults,
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
from .validation import build_validation_error_details

logger = logging.getLogger(__name__)


def _build_fastmcp() -> FastMCP:
    """Instantiate FastMCP with compatibility fallbacks for older SDK versions."""
    kwargs: dict[str, Any] = {
        "name": "git-context-controller",
        "instructions": (
            "Manage AI agent project context with Git-inspired operations. "
            "Use gcc_init, gcc_commit, gcc_branch, gcc_merge, gcc_context, gcc_status, "
            "gcc_log, gcc_list, gcc_checkout, gcc_delete, gcc_config_get, "
            "gcc_config_set, and gcc_config_list to checkpoint work, explore alternatives, "
            "operate branches, and recover structured history."
        ),
        "version": "0.1.0",
        "json_response": True,
    }
    optional_keys = ("version", "json_response")

    while True:
        try:
            return FastMCP(**kwargs)
        except TypeError as exc:
            message = str(exc).lower()
            if "unexpected keyword argument" not in message:
                raise

            removed_key = next((key for key in optional_keys if key in message and key in kwargs), None)
            if removed_key is None:
                raise
            kwargs.pop(removed_key, None)
            logger.debug(
                "FastMCP constructor does not support '%s'; using compatibility fallback.",
                removed_key,
            )


mcp = _build_fastmcp()

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

DESTRUCTIVE_WRITE_TOOL_ANNOTATIONS = {
    "readOnlyHint": False,
    "idempotentHint": False,
    "destructiveHint": True,
    "openWorldHint": False,
}


def _is_tool_annotation_kwarg_error(exc: TypeError) -> bool:
    """Return True when this SDK version does not support tool annotations kwarg."""
    message = str(exc).lower()
    return "annotations" in message or "unexpected keyword argument" in message


def _is_legacy_annotation_type_error(exc: TypeError) -> bool:
    """Return True when legacy FastMCP expects class annotations only."""
    return "issubclass() arg 1 must be a class" in str(exc).lower()


def _coerce_annotation_to_runtime_class(annotation: Any) -> type[Any]:
    """Convert complex typing annotations into a runtime class for legacy SDKs."""
    origin = get_origin(annotation)
    if origin is Annotated:
        args = get_args(annotation)
        if args:
            return _coerce_annotation_to_runtime_class(args[0])
        return object

    if origin in (Union, types.UnionType):
        non_none_args = [arg for arg in get_args(annotation) if arg is not type(None)]
        if len(non_none_args) == 1:
            return _coerce_annotation_to_runtime_class(non_none_args[0])
        return object

    if isinstance(origin, type):
        return origin

    if isinstance(annotation, type):
        return annotation
    if annotation is Any:
        return object

    return object


def _coerce_function_annotations_for_legacy_fastmcp(
    func: Callable[..., Any],
) -> dict[str, type[Any]]:
    """Resolve and coerce function annotations for legacy FastMCP introspection."""
    try:
        resolved = get_type_hints(func, globalns=func.__globals__, include_extras=True)
    except Exception:  # noqa: BLE001
        raw_annotations = dict(getattr(func, "__annotations__", {}))
        resolved: dict[str, Any] = {}
        for name, annotation in raw_annotations.items():
            if not isinstance(annotation, str):
                resolved[name] = annotation
                continue

            # Resolve each string annotation independently so one invalid symbol
            # does not block coercion of other annotations.
            def _probe() -> None:
                return None

            _probe.__annotations__ = {"value": annotation}
            try:
                resolved_value = get_type_hints(
                    _probe, globalns=func.__globals__, include_extras=True
                ).get("value", annotation)
            except Exception:  # noqa: BLE001
                resolved_value = annotation
            resolved[name] = resolved_value

    return {
        name: _coerce_annotation_to_runtime_class(annotation)
        for name, annotation in resolved.items()
    }


def _register_tool_with_legacy_annotation_fallback(
    func: Callable[..., Any],
    *,
    annotations: dict[str, bool] | None,
):
    """Register a tool after coercing type hints to class-based annotations."""
    original_annotations = dict(getattr(func, "__annotations__", {}))
    func.__annotations__ = _coerce_function_annotations_for_legacy_fastmcp(func)
    try:
        if annotations is None:
            return mcp.tool()(func)
        try:
            return mcp.tool(annotations=annotations)(func)
        except TypeError as exc:
            if _is_tool_annotation_kwarg_error(exc):
                logger.debug(
                    "FastMCP tool annotations not supported during legacy annotation fallback."
                )
                return mcp.tool()(func)
            raise
    finally:
        func.__annotations__ = original_annotations


def _register_tool(annotations: dict[str, bool]):
    """Register tool with annotations, with backwards-compatible fallback."""

    def decorator(func):
        try:
            return mcp.tool(annotations=annotations)(func)
        except TypeError as exc:
            if _is_legacy_annotation_type_error(exc):
                logger.debug(
                    "FastMCP requires class annotations during tool registration; using fallback."
                )
                return _register_tool_with_legacy_annotation_fallback(
                    func, annotations=annotations
                )
            if _is_tool_annotation_kwarg_error(exc):
                logger.debug(
                    "FastMCP tool annotations not supported in this SDK version; using fallback."
                )
                try:
                    return mcp.tool()(func)
                except TypeError as fallback_exc:
                    if _is_legacy_annotation_type_error(fallback_exc):
                        logger.debug(
                            "FastMCP requires class annotations during tool registration; "
                            "using fallback without tool annotations."
                        )
                        return _register_tool_with_legacy_annotation_fallback(
                            func, annotations=None
                        )
                    raise
            raise

    return decorator


def _error_payload_from_exception(exc: Exception) -> dict[str, Any]:
    """Convert internal exceptions into stable MCP error payloads."""
    if isinstance(exc, GCCError):
        payload = exc.to_payload()
    elif isinstance(exc, ValidationError):
        validation_details = build_validation_error_details(exc)
        suggestion = "Check field constraints and request schema."
        if validation_details.get("hints"):
            suggestion = "Check details.hints for schema conversion guidance and retry."
        payload = {
            "status": "error",
            "error_code": ErrorCode.INVALID_INPUT.value,
            "message": "Input validation failed",
            "suggestion": suggestion,
            "details": validation_details,
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


def _build_correlation_id() -> str:
    """Generate short operation correlation IDs for diagnostics."""
    return uuid.uuid4().hex[:12]


def _is_timeout_exception(exc: Exception) -> bool:
    """Return whether an exception represents timeout/deadline exhaustion."""
    if isinstance(exc, TimeoutError):
        return True
    message = str(exc).lower()
    timeout_markers = (
        "deadline has elapsed",
        "deadline exceeded",
        "timed out",
        "timeout",
    )
    return any(marker in message for marker in timeout_markers)


def _log_tool_phase(
    *,
    correlation_id: str,
    tool_name: str,
    phase: str,
    status: str,
    elapsed_seconds: float,
    details: dict[str, Any] | None = None,
) -> None:
    """Emit structured phase-level diagnostics for tool execution."""
    payload: dict[str, Any] = {
        "event_type": "mcp_tool_phase",
        "correlation_id": correlation_id,
        "tool_name": tool_name,
        "phase": phase,
        "status": status,
        "elapsed_ms": round(elapsed_seconds * 1000, 3),
    }
    if details:
        payload["details"] = details
    logger.info("mcp_tool_phase %s", json.dumps(payload, ensure_ascii=True, sort_keys=True))


def _run_tool(
    tool_name: str,
    request_payload: dict[str, Any],
    operation: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    """Execute tool operation and emit structured audit event."""
    total_start = time.perf_counter()
    correlation_id = _build_correlation_id()
    validation_start = time.perf_counter()
    enriched_request_payload = dict(request_payload)
    enriched_request_payload["correlation_id"] = correlation_id
    directory_resolution: dict[str, str] = {}
    directory = request_payload.get("directory")
    if isinstance(directory, str):
        try:
            directory_resolution = engine.resolve_directory(directory)
        except GCCError:
            directory_resolution = {}
        else:
            enriched_request_payload.update(directory_resolution)

    allowed, retry_after_seconds = rate_limiter.allow()
    validation_elapsed = time.perf_counter() - validation_start
    _log_tool_phase(
        correlation_id=correlation_id,
        tool_name=tool_name,
        phase="validation",
        status="ok" if allowed else "rate_limited",
        elapsed_seconds=validation_elapsed,
        details={"directory_resolution_applied": bool(directory_resolution)},
    )
    if not allowed:
        error_payload = GCCError(
            ErrorCode.RATE_LIMITED,
            f"Rate limit exceeded for tool '{tool_name}'",
            "Retry later or increase rate-limit-per-minute.",
            {"retry_after_seconds": retry_after_seconds},
        ).to_payload()
        error_payload["correlation_id"] = correlation_id
        _log_tool_phase(
            correlation_id=correlation_id,
            tool_name=tool_name,
            phase="total",
            status="error",
            elapsed_seconds=time.perf_counter() - total_start,
            details={"error_code": error_payload.get("error_code")},
        )
        audit_logger.log_tool_event(
            tool_name=tool_name,
            status="error",
            request_payload=enriched_request_payload,
            response_payload=error_payload,
        )
        return error_payload

    operation_start = time.perf_counter()
    try:
        response_payload = operation()
        operation_elapsed = time.perf_counter() - operation_start
        _log_tool_phase(
            correlation_id=correlation_id,
            tool_name=tool_name,
            phase="operation_execution",
            status="ok",
            elapsed_seconds=operation_elapsed,
        )
        serialization_start = time.perf_counter()
        json.dumps(response_payload, ensure_ascii=True, sort_keys=True)
        _log_tool_phase(
            correlation_id=correlation_id,
            tool_name=tool_name,
            phase="serialization",
            status="ok",
            elapsed_seconds=time.perf_counter() - serialization_start,
        )
        if isinstance(response_payload, dict):
            response_payload = dict(response_payload)
            response_payload["correlation_id"] = correlation_id
        if (
            directory_resolution
            and response_payload.get("status") == "success"
            and isinstance(response_payload, dict)
        ):
            response_payload = {**response_payload, **directory_resolution}
        _log_tool_phase(
            correlation_id=correlation_id,
            tool_name=tool_name,
            phase="total",
            status="ok",
            elapsed_seconds=time.perf_counter() - total_start,
        )
        audit_logger.log_tool_event(
            tool_name=tool_name,
            status="success",
            request_payload=enriched_request_payload,
            response_payload=response_payload,
        )
        return response_payload
    except Exception as exc:  # noqa: BLE001
        operation_elapsed = time.perf_counter() - operation_start
        timeout_detected = _is_timeout_exception(exc)
        phase_details = {"exception": exc.__class__.__name__}
        if timeout_detected:
            _log_tool_phase(
                correlation_id=correlation_id,
                tool_name=tool_name,
                phase="operation_execution",
                status="timeout",
                elapsed_seconds=operation_elapsed,
                details=phase_details,
            )
            error_payload = GCCError(
                ErrorCode.TIMEOUT,
                f"Tool '{tool_name}' timed out.",
                "Retry the request and provide correlation_id for server-side trace lookup.",
                {
                    "phase": "operation_execution",
                    "elapsed_ms": round(operation_elapsed * 1000, 3),
                },
            ).to_payload()
        else:
            _log_tool_phase(
                correlation_id=correlation_id,
                tool_name=tool_name,
                phase="operation_execution",
                status="error",
                elapsed_seconds=operation_elapsed,
                details=phase_details,
            )
            error_payload = _error_payload_from_exception(exc)
        error_payload["correlation_id"] = correlation_id
        if directory_resolution:
            error_payload = {**error_payload, **directory_resolution}
        _log_tool_phase(
            correlation_id=correlation_id,
            tool_name=tool_name,
            phase="total",
            status="error",
            elapsed_seconds=time.perf_counter() - total_start,
            details={"error_code": error_payload.get("error_code")},
        )
        audit_logger.log_tool_event(
            tool_name=tool_name,
            status="error",
            request_payload=enriched_request_payload,
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
        Field(
            description=(
                "Key achievements completed in this checkpoint (list[str]). "
                "Example: ['Added parser', 'Added tests']."
            )
        ),
    ] = None,
    files_modified: Annotated[
        list[str] | None,
        Field(
            description=(
                "Files modified for this checkpoint (list[str]). "
                "Example: ['src/gcc_mcp/server.py']."
            )
        ),
    ] = None,
    tests_passed: Annotated[bool, Field(description="Whether tests passed")] = True,
    notes: Annotated[str, Field(description="Additional notes for the checkpoint")] = "",
    tags: Annotated[
        list[str] | None,
        Field(description="Tags for categorization (list[str]). Example: ['mcp', 'docs']."),
    ] = None,
    ota_log: Annotated[
        dict[str, str] | None,
        Field(
            description=(
                "Observation-Thought-Action-Result details (dict[str, str]). "
                "Example: {'observation':'...','thought':'...','action':'...','result':'...'}."
            )
        ),
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
    tags: Annotated[
        list[str] | None,
        Field(
            description=(
                "Tags for branch categorization (list[str]). "
                "Example: ['mcp', 'api']."
            )
        ),
    ] = None,
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
        Field(
            description=(
                "Branch names to include in context output (list[str]). "
                "Example: ['main', 'feature-a']."
            )
        ),
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


@_register_tool(READ_ONLY_TOOL_ANNOTATIONS)
def gcc_config_list(
    directory: Annotated[str, Field(description="Path to GCC-enabled directory")],
) -> dict[str, Any]:
    """List GCC configuration values."""
    request_payload = {"directory": directory}

    def _operation() -> dict[str, Any]:
        return {
            "status": "success",
            "message": "Config listed",
            "config": engine.get_config(directory),
        }

    return _run_tool("gcc_config_list", request_payload=request_payload, operation=_operation)


@_register_tool(READ_ONLY_TOOL_ANNOTATIONS)
def gcc_config_get(
    directory: Annotated[str, Field(description="Path to GCC-enabled directory")],
    key: Annotated[str, Field(min_length=1, description="Configuration key to fetch")],
) -> dict[str, Any]:
    """Retrieve one GCC configuration value."""
    request_payload = {"directory": directory, "key": key}

    def _operation() -> dict[str, Any]:
        config = engine.get_config(directory)
        return {
            "status": "success",
            "message": "Config value retrieved",
            "key": key,
            "value": config.get(key),
        }

    return _run_tool("gcc_config_get", request_payload=request_payload, operation=_operation)


@_register_tool(WRITE_TOOL_ANNOTATIONS)
def gcc_config_set(
    directory: Annotated[str, Field(description="Path to GCC-enabled directory")],
    key: Annotated[str, Field(min_length=1, description="Mutable configuration key")],
    value: Annotated[
        bool | int | float | str,
        Field(description="Configuration value to set"),
    ],
) -> dict[str, Any]:
    """Set a mutable GCC configuration value."""
    request_payload = {"directory": directory, "key": key, "value": value}

    def _operation() -> dict[str, Any]:
        updated = engine.set_config(directory, key, value)
        return {
            "status": "success",
            "message": f"Config key '{key}' updated",
            "config": updated,
        }

    return _run_tool("gcc_config_set", request_payload=request_payload, operation=_operation)


@_register_tool(READ_ONLY_TOOL_ANNOTATIONS)
def gcc_list(
    directory: Annotated[str, Field(description="Path to GCC-enabled directory")],
    active_only: Annotated[
        bool,
        Field(description="Return only active branches"),
    ] = False,
    archived_only: Annotated[
        bool,
        Field(description="Return only archived/abandoned branches"),
    ] = False,
    tags: Annotated[
        list[str] | None,
        Field(description="Optional branch tag filters"),
    ] = None,
) -> dict[str, Any]:
    """List GCC branches with optional filters."""
    request_payload = {
        "directory": directory,
        "active_only": active_only,
        "archived_only": archived_only,
        "tags": tags or [],
    }

    def _operation() -> dict[str, Any]:
        return engine.list_branches(
            directory=directory,
            active_only=active_only,
            archived_only=archived_only,
            tags=tags or [],
        )

    return _run_tool("gcc_list", request_payload=request_payload, operation=_operation)


@_register_tool(READ_ONLY_TOOL_ANNOTATIONS)
def gcc_log(
    directory: Annotated[str, Field(description="Path to GCC-enabled directory")],
    branch: Annotated[
        str | None,
        Field(description="Branch name (defaults to current branch)"),
    ] = None,
    limit: Annotated[
        int,
        Field(ge=0, description="Maximum entries (0 keeps all matched entries)"),
    ] = 20,
    since: Annotated[
        str | None,
        Field(description="Optional date filter in YYYY-MM-DD format"),
    ] = None,
    commit_type: Annotated[
        str | None,
        Field(description="Optional type filter: feature, bugfix, refactor, test, docs, chore, merge"),
    ] = None,
    tags: Annotated[
        list[str] | None,
        Field(description="Optional tag filters"),
    ] = None,
) -> dict[str, Any]:
    """Retrieve commit history for a branch."""
    request_payload = {
        "directory": directory,
        "branch": branch,
        "limit": limit,
        "since": since,
        "commit_type": commit_type,
        "tags": tags or [],
    }

    def _operation() -> dict[str, Any]:
        since_date: date | None = None
        if since:
            try:
                since_date = date.fromisoformat(since)
            except ValueError as exc:
                raise GCCError(
                    ErrorCode.INVALID_INPUT,
                    "Invalid since date format.",
                    "Use YYYY-MM-DD.",
                ) from exc

        allowed_types = {"feature", "bugfix", "refactor", "test", "docs", "chore", "merge"}
        normalized_commit_type = str(commit_type).strip() if commit_type else ""
        if normalized_commit_type and normalized_commit_type not in allowed_types:
            raise GCCError(
                ErrorCode.INVALID_INPUT,
                "Invalid commit_type filter.",
                "Use one of: feature, bugfix, refactor, test, docs, chore, merge.",
            )

        return engine.get_log(
            directory=directory,
            branch_name=branch,
            limit=limit,
            since=since_date,
            commit_type=normalized_commit_type or None,
            tags=tags or [],
        )

    return _run_tool("gcc_log", request_payload=request_payload, operation=_operation)


@_register_tool(WRITE_TOOL_ANNOTATIONS)
def gcc_checkout(
    directory: Annotated[str, Field(description="Path to GCC-enabled directory")],
    branch: Annotated[
        str,
        Field(
            min_length=1,
            max_length=50,
            pattern=r"^[a-z0-9-]+$",
            description="Branch name to make current",
        ),
    ],
) -> dict[str, Any]:
    """Switch the active GCC branch."""
    request_payload = {"directory": directory, "branch": branch}

    def _operation() -> dict[str, Any]:
        return engine.checkout_branch(directory, branch)

    return _run_tool("gcc_checkout", request_payload=request_payload, operation=_operation)


@_register_tool(DESTRUCTIVE_WRITE_TOOL_ANNOTATIONS)
def gcc_delete(
    directory: Annotated[str, Field(description="Path to GCC-enabled directory")],
    branch: Annotated[
        str,
        Field(
            min_length=1,
            max_length=50,
            pattern=r"^[a-z0-9-]+$",
            description="Branch name to archive/delete",
        ),
    ],
    force: Annotated[
        bool,
        Field(description="Permanently delete branch directory"),
    ] = False,
    archive: Annotated[
        bool,
        Field(description="Mark branch as archived/abandoned"),
    ] = False,
) -> dict[str, Any]:
    """Archive or force-delete a GCC branch."""
    request_payload = {
        "directory": directory,
        "branch": branch,
        "force": force,
        "archive": archive,
    }

    def _operation() -> dict[str, Any]:
        return engine.delete_branch(
            directory=directory,
            branch_name=branch,
            force=force,
            archive=archive,
        )

    return _run_tool("gcc_delete", request_payload=request_payload, operation=_operation)


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


def _effective_runtime_config_payload(
    *,
    transport: str,
    host: str,
    port: int,
    allow_public_http: bool,
    audit_log_file: str,
    audit_redact_sensitive: bool,
    rate_limit_per_minute: int,
    audit_max_field_chars: int,
    security_profile: str,
    runtime_auth: RuntimeAuthDefaults,
    runtime_policy: RuntimeSecurityPolicyDefaults,
    runtime_path_resolution: RuntimePathResolutionDefaults,
    resolved_audit_signing_key: str,
) -> dict[str, Any]:
    """Build sanitized runtime configuration output for preflight diagnostics."""
    if resolved_audit_signing_key:
        if runtime_policy.audit_signing_key_file:
            signing_key_source = "file"
        elif runtime_policy.audit_signing_key:
            signing_key_source = "value"
        else:
            signing_key_source = "resolved"
    else:
        signing_key_source = "none"

    return {
        "transport": transport,
        "host": host,
        "port": port,
        "allow_public_http": allow_public_http,
        "audit": {
            "log_file": audit_log_file or None,
            "redact_sensitive": audit_redact_sensitive,
            "max_field_chars": audit_max_field_chars,
        },
        "rate_limit_per_minute": rate_limit_per_minute,
        "security_profile": security_profile,
        "audit_signing": {
            "enabled": bool(resolved_audit_signing_key),
            "key_source": signing_key_source,
            "key_id": runtime_policy.audit_signing_key_id or None,
        },
        "path_resolution": {
            "path_mappings": [
                {"from": source, "to": target}
                for source, target in runtime_path_resolution.path_mappings
            ],
            "allowed_roots": list(runtime_path_resolution.allowed_roots),
        },
        "auth": {
            "mode": runtime_auth.auth_mode,
            "required_scopes": list(runtime_auth.auth_required_scopes),
            "token_configured": bool(runtime_auth.auth_token),
            "trusted_proxy_header": runtime_auth.trusted_proxy_header or None,
            "trusted_proxy_value_configured": bool(runtime_auth.trusted_proxy_value),
            "oauth2_introspection_url": runtime_auth.oauth2_introspection_url or None,
            "oauth2_client_id": runtime_auth.oauth2_client_id or None,
            "oauth2_client_secret_configured": bool(runtime_auth.oauth2_client_secret),
            "oauth2_introspection_timeout_seconds": (
                runtime_auth.oauth2_introspection_timeout_seconds
            ),
            "auth_issuer_url": runtime_auth.auth_issuer_url or None,
            "auth_resource_server_url": runtime_auth.auth_resource_server_url or None,
        },
    }


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
        path_resolution_defaults = get_runtime_path_resolution_defaults()
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
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="Validate runtime settings and exit without starting server transport.",
    )
    parser.add_argument(
        "--print-effective-config",
        action="store_true",
        help="Print sanitized effective runtime configuration and exit.",
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
    global engine
    global rate_limiter
    engine = GCCEngine(
        path_mappings=path_resolution_defaults.path_mappings,
        allowed_roots=path_resolution_defaults.allowed_roots,
    )
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

    if args.print_effective_config:
        print(
            json.dumps(
                _effective_runtime_config_payload(
                    transport=str(args.transport),
                    host=str(args.host),
                    port=int(args.port),
                    allow_public_http=bool(args.allow_public_http),
                    audit_log_file=audit_path,
                    audit_redact_sensitive=bool(args.audit_redact_sensitive),
                    rate_limit_per_minute=int(args.rate_limit_per_minute),
                    audit_max_field_chars=int(args.audit_max_field_chars),
                    security_profile=runtime_policy.security_profile,
                    runtime_auth=runtime_auth,
                    runtime_policy=runtime_policy,
                    runtime_path_resolution=path_resolution_defaults,
                    resolved_audit_signing_key=resolved_audit_signing_key,
                ),
                indent=2,
                sort_keys=True,
            )
        )

    if args.check_config or args.print_effective_config:
        if not args.print_effective_config:
            print("Configuration is valid.")
        return

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
