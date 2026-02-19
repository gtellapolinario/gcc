"""MCP server entrypoint and tool definitions for GCC."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Annotated, Any, Callable

from mcp.server.fastmcp import FastMCP
from pydantic import Field, ValidationError

from .audit import AuditLogger
from .engine import GCCEngine
from .errors import ErrorCode, GCCError
from .models import (
    BranchRequest,
    CommitRequest,
    ContextRequest,
    InitRequest,
    MergeRequest,
    StatusRequest,
)
from .runtime import (
    get_runtime_defaults,
    get_runtime_security_defaults,
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
        "ota_log": ota_log or {},
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
    args = parser.parse_args()

    try:
        validate_streamable_http_binding(
            transport=args.transport,
            host=args.host,
            allow_public_http=args.allow_public_http,
        )
    except ValueError as exc:
        parser.error(str(exc))

    global audit_logger
    audit_path = str(args.audit_log_file).strip()
    audit_logger = AuditLogger(
        log_path=Path(audit_path) if audit_path else None,
        redact_sensitive=bool(args.audit_redact_sensitive),
    )

    if args.transport == "stdio":
        mcp.run()
        return

    mcp.run(transport="streamable-http", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
