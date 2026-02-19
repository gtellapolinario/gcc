"""Command line interface for GCC with parity to MCP tools."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from pydantic import ValidationError

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

engine = GCCEngine()


def _csv_list(value: str) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _print_payload(payload: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2))
        return

    status = payload.get("status", "unknown").upper()
    message = payload.get("message", "")
    print(f"[{status}] {message}")

    if payload.get("status") == "error":
        error_code = payload.get("error_code", "")
        suggestion = payload.get("suggestion", "")
        if error_code:
            print(f"error_code: {error_code}")
        if suggestion:
            print(f"suggestion: {suggestion}")
        return

    for key in (
        "commit_id",
        "branch",
        "branch_name",
        "merged_from",
        "merged_into",
        "current_branch",
        "project_name",
        "git_context_policy",
        "security_notice",
    ):
        if key in payload and payload[key] not in ("", None):
            print(f"{key}: {payload[key]}")


def _error_payload(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, GCCError):
        return exc.to_payload()
    if isinstance(exc, ValidationError):
        errors: Any
        try:
            errors = exc.errors(include_context=False, include_input=False)
        except TypeError:
            errors = exc.errors()
        return {
            "status": "error",
            "error_code": ErrorCode.INVALID_INPUT.value,
            "message": "Input validation failed",
            "suggestion": "Check command arguments and constraints.",
            "details": {"errors": errors},
        }
    return {
        "status": "error",
        "error_code": ErrorCode.INTERNAL_ERROR.value,
        "message": str(exc),
        "suggestion": "Retry with --json for diagnostics and inspect logs.",
        "details": {},
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="gcc-cli", description="Git Context Controller CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="Initialize GCC in a repository directory")
    init.add_argument("-d", "--directory", default=".", help="Target repository directory")
    init.add_argument("--name", required=True, help="Project name")
    init.add_argument("--description", default="", help="Project description")
    init.add_argument("--goals", default="", help="Comma-separated initial goals")
    init.add_argument(
        "--git-context-policy",
        choices=["ignore", "track"],
        default="ignore",
        help="ignore=.GCC added to .gitignore (default), track=.GCC tracked in git",
    )
    init.add_argument(
        "--ack-sensitive-context-risk",
        action="store_true",
        help="Required with --git-context-policy track",
    )
    init.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    commit = subparsers.add_parser("commit", help="Create a GCC checkpoint")
    commit.add_argument("-d", "--directory", default=".", help="GCC directory")
    commit.add_argument("-m", "--message", required=True, help="Commit message")
    commit.add_argument(
        "--type",
        choices=["feature", "bugfix", "refactor", "test", "docs", "chore"],
        default="feature",
        help="Commit type",
    )
    commit.add_argument("--details", default="", help="Comma-separated achievement details")
    commit.add_argument("--files", default="", help="Comma-separated modified file paths")
    tests_group = commit.add_mutually_exclusive_group()
    tests_group.add_argument("--tests-passed", action="store_true", help="Mark tests passed")
    tests_group.add_argument("--tests-failed", action="store_true", help="Mark tests failed")
    commit.add_argument("--notes", default="", help="Additional notes")
    commit.add_argument("--tags", default="", help="Comma-separated tags")
    commit.add_argument("--observation", default="", help="OTA observation")
    commit.add_argument("--thought", default="", help="OTA thought")
    commit.add_argument("--action", default="", help="OTA action")
    commit.add_argument("--result", default="", help="OTA result")
    commit.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    branch = subparsers.add_parser("branch", help="Create a GCC branch")
    branch.add_argument("name", help="Branch name")
    branch.add_argument("-d", "--directory", default=".", help="GCC directory")
    branch.add_argument("--description", required=True, help="Branch description")
    branch.add_argument("--from-branch", default="main", help="Parent branch")
    branch.add_argument(
        "--no-copy-context",
        action="store_true",
        help="Do not copy parent context summary",
    )
    branch.add_argument("--tags", default="", help="Comma-separated tags")
    branch.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    merge = subparsers.add_parser("merge", help="Merge one GCC branch into another")
    merge.add_argument("source_branch", help="Source branch")
    merge.add_argument("-d", "--directory", default=".", help="GCC directory")
    merge.add_argument("--summary", required=True, help="Merge summary")
    merge.add_argument("--target-branch", default="main", help="Target branch")
    merge.add_argument("--keep-branch", action="store_true", help="Keep source branch active")
    merge.add_argument(
        "--no-roadmap-update",
        action="store_true",
        help="Do not append merge note to main.md",
    )
    merge.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    context = subparsers.add_parser("context", help="Retrieve GCC context")
    context.add_argument("-d", "--directory", default=".", help="GCC directory")
    context.add_argument(
        "--level", choices=["summary", "detailed", "full"], default="summary", help="Context depth"
    )
    context.add_argument("--scope", default="", help="Comma-separated branches to include")
    context.add_argument("--since", default="", help="Filter commits since YYYY-MM-DD")
    context.add_argument("--tags", default="", help="Comma-separated tags")
    context.add_argument(
        "--format",
        choices=["markdown", "json", "yaml"],
        default="markdown",
        help="Rendered context format",
    )
    context.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    status = subparsers.add_parser("status", help="Show GCC status")
    status.add_argument("-d", "--directory", default=".", help="GCC directory")
    status.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    as_json = bool(getattr(args, "json", False))

    try:
        if args.command == "init":
            response = engine.initialize(
                InitRequest(
                    directory=args.directory,
                    project_name=args.name,
                    project_description=args.description,
                    initial_goals=_csv_list(args.goals),
                    git_context_policy=args.git_context_policy,
                    acknowledge_sensitive_data_risk=args.ack_sensitive_context_risk,
                )
            ).model_dump(mode="json")
        elif args.command == "commit":
            tests_passed = True
            if args.tests_failed:
                tests_passed = False
            elif args.tests_passed:
                tests_passed = True

            ota_payload: dict[str, str] | None = None
            if any([args.observation, args.thought, args.action, args.result]):
                ota_payload = {
                    "observation": args.observation,
                    "thought": args.thought,
                    "action": args.action,
                    "result": args.result,
                }

            response = engine.commit(
                CommitRequest(
                    directory=args.directory,
                    message=args.message,
                    commit_type=args.type,
                    details=_csv_list(args.details),
                    files_modified=_csv_list(args.files),
                    tests_passed=tests_passed,
                    notes=args.notes,
                    tags=_csv_list(args.tags),
                    ota_log=ota_payload,
                )
            ).model_dump(mode="json")
        elif args.command == "branch":
            response = engine.branch(
                BranchRequest(
                    directory=args.directory,
                    name=args.name,
                    description=args.description,
                    from_branch=args.from_branch,
                    copy_context=not args.no_copy_context,
                    tags=_csv_list(args.tags),
                )
            ).model_dump(mode="json")
        elif args.command == "merge":
            response = engine.merge(
                MergeRequest(
                    directory=args.directory,
                    source_branch=args.source_branch,
                    target_branch=args.target_branch,
                    summary=args.summary,
                    keep_branch=args.keep_branch,
                    update_roadmap=not args.no_roadmap_update,
                )
            ).model_dump(mode="json")
        elif args.command == "context":
            response = engine.get_context(
                ContextRequest(
                    directory=args.directory,
                    level=args.level,
                    scope=_csv_list(args.scope),
                    since=args.since or None,
                    tags=_csv_list(args.tags),
                    format=args.format,
                )
            ).model_dump(mode="json")
        else:
            response = engine.get_status(StatusRequest(directory=args.directory)).model_dump(mode="json")

        _print_payload(response, as_json=as_json)
        return 0
    except Exception as exc:  # noqa: BLE001
        payload = _error_payload(exc)
        _print_payload(payload, as_json=as_json)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
