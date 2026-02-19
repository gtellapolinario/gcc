"""MCP server entrypoint and tool definitions for GCC."""

from __future__ import annotations

import argparse
import logging
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field, ValidationError

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


def _error_payload_from_exception(exc: Exception) -> dict[str, Any]:
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


@mcp.tool()
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
    try:
        request = InitRequest(
            directory=directory,
            project_name=project_name,
            project_description=project_description,
            initial_goals=initial_goals or [],
            git_context_policy=git_context_policy,
            acknowledge_sensitive_data_risk=acknowledge_sensitive_data_risk,
        )
        return engine.initialize(request).model_dump(mode="json")
    except Exception as exc:  # noqa: BLE001
        return _error_payload_from_exception(exc)


@mcp.tool()
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
    try:
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
    except Exception as exc:  # noqa: BLE001
        return _error_payload_from_exception(exc)


@mcp.tool()
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
    try:
        request = BranchRequest(
            directory=directory,
            name=name,
            description=description,
            from_branch=from_branch,
            copy_context=copy_context,
            tags=tags or [],
        )
        return engine.branch(request).model_dump(mode="json")
    except Exception as exc:  # noqa: BLE001
        return _error_payload_from_exception(exc)


@mcp.tool()
def gcc_merge(
    directory: Annotated[str, Field(description="Path to GCC-enabled directory")],
    source_branch: Annotated[str, Field(description="Branch to merge from")],
    summary: Annotated[str, Field(min_length=1, max_length=500, description="Merge summary")],
    target_branch: Annotated[str, Field(description="Branch to merge into")] = "main",
    keep_branch: Annotated[bool, Field(description="Keep source branch after merge")] = False,
    update_roadmap: Annotated[bool, Field(description="Update roadmap notes in main.md")] = True,
) -> dict[str, Any]:
    """Merge a completed branch into a target branch."""
    try:
        request = MergeRequest(
            directory=directory,
            source_branch=source_branch,
            target_branch=target_branch,
            summary=summary,
            keep_branch=keep_branch,
            update_roadmap=update_roadmap,
        )
        return engine.merge(request).model_dump(mode="json")
    except Exception as exc:  # noqa: BLE001
        return _error_payload_from_exception(exc)


@mcp.tool()
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
) -> dict[str, Any]:
    """Retrieve context snapshots across branches."""
    try:
        request = ContextRequest(
            directory=directory,
            level=level,
            scope=scope or [],
            since=since,
            tags=tags or [],
            format=format,
        )
        return engine.get_context(request).model_dump(mode="json")
    except Exception as exc:  # noqa: BLE001
        return _error_payload_from_exception(exc)


@mcp.tool()
def gcc_status(
    directory: Annotated[str, Field(description="Path to GCC-enabled directory")],
) -> dict[str, Any]:
    """Get a quick status summary for a GCC project."""
    try:
        request = StatusRequest(directory=directory)
        return engine.get_status(request).model_dump(mode="json")
    except Exception as exc:  # noqa: BLE001
        return _error_payload_from_exception(exc)


def main() -> None:
    parser = argparse.ArgumentParser(description="GCC MCP server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http"],
        default="stdio",
        help="Server transport mode (default: stdio).",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host for streamable HTTP transport.")
    parser.add_argument("--port", type=int, default=8000, help="Port for streamable HTTP transport.")
    args = parser.parse_args()

    if args.transport == "stdio":
        mcp.run()
        return

    mcp.run(transport="streamable-http", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
