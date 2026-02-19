"""Command line interface for GCC with parity to MCP tools."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .audit import verify_signed_audit_log
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
from .runtime import resolve_audit_signing_key

engine = GCCEngine()


def _csv_list(value: str) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _load_signing_keyring(path_value: str) -> dict[str, str]:
    keyring_path = Path(path_value).expanduser()
    try:
        payload = json.loads(keyring_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise GCCError(
            ErrorCode.INVALID_INPUT,
            "Unable to read signing-keyring-file.",
            "Ensure --signing-keyring-file points to a readable JSON file.",
        ) from exc
    except json.JSONDecodeError as exc:
        raise GCCError(
            ErrorCode.INVALID_INPUT,
            "signing-keyring-file must contain valid JSON object mapping key ids to keys.",
            "Provide JSON like {\"k1\": \"secret1\", \"k2\": \"secret2\"}.",
        ) from exc

    if not isinstance(payload, dict):
        raise GCCError(
            ErrorCode.INVALID_INPUT,
            "signing-keyring-file must contain a JSON object.",
            "Provide JSON like {\"k1\": \"secret1\", \"k2\": \"secret2\"}.",
        )

    keyring: dict[str, str] = {}
    for key_id, key_value in payload.items():
        if not isinstance(key_id, str) or not key_id.strip():
            raise GCCError(
                ErrorCode.INVALID_INPUT,
                "signing-keyring-file contains empty key id or key.",
                "All key ids must be non-empty strings.",
            )
        if not isinstance(key_value, str) or not key_value.strip():
            raise GCCError(
                ErrorCode.INVALID_INPUT,
                "signing-keyring-file contains empty key id or key.",
                "All key values must be non-empty strings.",
            )
        normalized_key_id = key_id.strip()
        normalized_key_value = key_value.strip()
        if normalized_key_id in keyring:
            raise GCCError(
                ErrorCode.INVALID_INPUT,
                "signing-keyring-file contains duplicate key ids.",
                "Use unique key ids after trimming whitespace.",
            )
        keyring[normalized_key_id] = normalized_key_value
    return keyring


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
        "count",
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

    if "config" in payload and isinstance(payload["config"], dict):
        print("config:")
        for config_key, config_value in payload["config"].items():
            print(f"  {config_key}: {config_value}")

    if "values" in payload and isinstance(payload["values"], dict):
        print("values:")
        for config_key, config_value in payload["values"].items():
            print(f"  {config_key}: {config_value}")

    if "key" in payload and "value" in payload:
        print(f"{payload['key']}: {payload.get('value')}")

    if "branches" in payload:
        for branch in payload["branches"]:
            marker = "*" if branch.get("current") else "-"
            print(
                f"{marker} {branch.get('name')} [{branch.get('status')}] "
                f"integration={branch.get('integration_status')} commits={branch.get('commit_count')}"
            )

    if "entries" in payload:
        for entry in payload["entries"]:
            print(
                f"- [{entry.get('timestamp','')}] {entry.get('type','')} "
                f"{entry.get('id','')}: {entry.get('message','')}"
            )


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
    context.add_argument(
        "--redact-sensitive",
        action="store_true",
        help="Redact potentially sensitive values in context output",
    )
    context.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    status = subparsers.add_parser("status", help="Show GCC status")
    status.add_argument("-d", "--directory", default=".", help="GCC directory")
    status.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    config = subparsers.add_parser("config", help="Get or set GCC config values")
    config.add_argument("-d", "--directory", default=".", help="GCC directory")
    config.add_argument("key", nargs="?", help="Config key")
    config.add_argument("value", nargs="?", help="Config value to set")
    config.add_argument("--list", action="store_true", help="List all config values")
    config.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    log = subparsers.add_parser("log", help="Show commit history for a branch")
    log.add_argument("branch", nargs="?", help="Branch name (defaults to current)")
    log.add_argument("-d", "--directory", default=".", help="GCC directory")
    log.add_argument("-n", "--limit", type=int, default=20, help="Limit number of commits")
    log.add_argument("--since", default="", help="Filter since date YYYY-MM-DD")
    log.add_argument(
        "--type",
        choices=["feature", "bugfix", "refactor", "test", "docs", "chore", "merge"],
        default="",
        help="Filter by commit type",
    )
    log.add_argument("--tags", default="", help="Comma-separated tags")
    log.add_argument("--oneline", action="store_true", help="One line output format")
    log.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    list_cmd = subparsers.add_parser("list", help="List branches")
    list_cmd.add_argument("-d", "--directory", default=".", help="GCC directory")
    list_cmd.add_argument("--active", action="store_true", help="Show only active branches")
    list_cmd.add_argument("--archived", action="store_true", help="Show only archived branches")
    list_cmd.add_argument("--tags", default="", help="Comma-separated tags")
    list_cmd.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    checkout = subparsers.add_parser("checkout", help="Switch active GCC branch")
    checkout.add_argument("branch", help="Branch name")
    checkout.add_argument("-d", "--directory", default=".", help="GCC directory")
    checkout.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    delete = subparsers.add_parser("delete", help="Archive or delete a GCC branch")
    delete.add_argument("branch", help="Branch name")
    delete.add_argument("-d", "--directory", default=".", help="GCC directory")
    delete.add_argument("--force", action="store_true", help="Force delete branch directory")
    delete.add_argument("--archive", action="store_true", help="Archive branch instead of deleting")
    delete.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    audit_verify = subparsers.add_parser(
        "audit-verify",
        help="Verify signed GCC audit log integrity",
    )
    audit_verify.add_argument(
        "--log-file",
        required=True,
        help="Path to JSONL audit log file",
    )
    audit_verify.add_argument(
        "--signing-key",
        default=os.environ.get("GCC_MCP_AUDIT_SIGNING_KEY", ""),
        help="HMAC signing key used to sign audit events (default: env var).",
    )
    audit_verify.add_argument(
        "--signing-key-file",
        default=os.environ.get("GCC_MCP_AUDIT_SIGNING_KEY_FILE", ""),
        help="Optional file path containing signing key; safer than inline key.",
    )
    audit_verify.add_argument(
        "--signing-keyring-file",
        default=os.environ.get("GCC_MCP_AUDIT_SIGNING_KEYRING_FILE", ""),
        help="Optional JSON file mapping signing key ids to keys for rotated logs.",
    )
    audit_verify.add_argument("--json", action="store_true", help="Output machine-readable JSON")

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
                    redact_sensitive=args.redact_sensitive,
                )
            ).model_dump(mode="json")
        elif args.command == "config":
            if args.list:
                response = {
                    "status": "success",
                    "message": "Config listed",
                    "config": engine.get_config(args.directory),
                }
            elif args.key and args.value is not None:
                response = {
                    "status": "success",
                    "message": f"Config key '{args.key}' updated",
                    "config": engine.set_config(args.directory, args.key, args.value),
                }
            elif args.key:
                config = engine.get_config(args.directory)
                response = {
                    "status": "success",
                    "message": "Config value retrieved",
                    "key": args.key,
                    "value": config.get(args.key),
                }
            else:
                raise GCCError(
                    ErrorCode.INVALID_INPUT,
                    "config requires --list or <key> [value]",
                    "Use `gcc-cli config --list` or `gcc-cli config <key> [value]`.",
                )
        elif args.command == "log":
            since: date | None = None
            if args.since:
                try:
                    since = date.fromisoformat(args.since)
                except ValueError as exc:
                    raise GCCError(
                        ErrorCode.INVALID_INPUT,
                        "Invalid --since date format",
                        "Use YYYY-MM-DD.",
                    ) from exc
            response = engine.get_log(
                directory=args.directory,
                branch_name=args.branch,
                limit=args.limit,
                since=since,
                commit_type=args.type or None,
                tags=_csv_list(args.tags),
            )
            if args.oneline and not as_json:
                for entry in response.get("entries", []):
                    print(
                        f"{entry.get('id','')} "
                        f"{entry.get('type','')} "
                        f"{entry.get('message','')}"
                    )
                return 0
        elif args.command == "list":
            response = engine.list_branches(
                directory=args.directory,
                active_only=args.active,
                archived_only=args.archived,
                tags=_csv_list(args.tags),
            )
        elif args.command == "checkout":
            response = engine.checkout_branch(args.directory, args.branch)
        elif args.command == "delete":
            response = engine.delete_branch(
                directory=args.directory,
                branch_name=args.branch,
                force=args.force,
                archive=args.archive,
            )
        elif args.command == "audit-verify":
            try:
                signing_key = resolve_audit_signing_key(
                    audit_signing_key=str(args.signing_key),
                    audit_signing_key_file=str(args.signing_key_file),
                )
            except ValueError as exc:
                raise GCCError(
                    ErrorCode.INVALID_INPUT,
                    str(exc),
                    "Provide signing key via --signing-key-file or GCC_MCP_AUDIT_SIGNING_KEY.",
                ) from exc

            keyring: dict[str, str] = {}
            if str(args.signing_keyring_file).strip():
                keyring = _load_signing_keyring(str(args.signing_keyring_file))

            response = verify_signed_audit_log(
                log_path=Path(args.log_file),
                signing_key=signing_key,
                signing_keyring=keyring,
            )
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
