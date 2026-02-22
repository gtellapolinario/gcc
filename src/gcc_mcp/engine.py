"""Core GCC engine implementing all domain operations."""

from __future__ import annotations

import re
import shutil
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .constants import (
    BRANCHES_DIR_NAME,
    COMMIT_FILE_NAME,
    CONFIG_FILE_NAME,
    DEFAULT_BRANCH,
    GCC_DIR_NAME,
    LOG_FILE_NAME,
    MAIN_FILE_NAME,
    MAX_ACTIVITY_ENTRIES,
    METADATA_FILE_NAME,
)
from .errors import ErrorCode, GCCError
from .file_manager import FileManager
from .models import (
    BranchRequest,
    BranchResponse,
    CommitRequest,
    CommitResponse,
    ContextFormat,
    ContextRequest,
    ContextResponse,
    GitContextPolicy,
    InitRequest,
    InitResponse,
    MergeRequest,
    MergeResponse,
    StatusRequest,
    StatusResponse,
)

BRANCH_NAME_PATTERN = re.compile(r"^[a-z0-9-]+$")
SENSITIVE_CONTEXT_NOTICE = (
    ".GCC can contain sensitive or security-relevant context (reasoning traces, "
    "credentials, architecture details). Decide explicitly whether this directory should "
    "be tracked in Git for each repository."
)
REDACTION_NOTICE = (
    "Context data may include sensitive content. Enable redaction with "
    "context.redact_sensitive=true or set config redaction_mode=true."
)
SKILL_TEMPLATE_CHOICES = {"codex", "generic"}


class GCCEngine:
    """Main service implementing GCC operations."""

    def __init__(
        self,
        file_manager: FileManager | None = None,
        path_mappings: list[tuple[str, str]] | tuple[tuple[str, str], ...] | None = None,
        allowed_roots: list[str] | tuple[str, ...] | None = None,
    ) -> None:
        """Create an engine instance with filesystem operations dependency."""
        self.file_manager = file_manager or FileManager()
        self._path_mappings = self._normalize_path_mappings(path_mappings or [])
        self._allowed_roots = self._normalize_allowed_roots(allowed_roots or [])

    def initialize(self, request: InitRequest) -> InitResponse:
        """Initialize `.GCC` state for a repository directory."""
        directory = self._resolve_existing_directory(request.directory)
        gcc_dir = directory / GCC_DIR_NAME
        if gcc_dir.exists():
            raise GCCError(
                ErrorCode.GCC_ALREADY_INITIALIZED,
                f"GCC already initialized in {directory}",
                "Use a different directory or remove the existing .GCC folder.",
                {"gcc_directory": str(gcc_dir)},
            )

        timestamp = self._now_iso()
        branches_dir = gcc_dir / BRANCHES_DIR_NAME
        main_branch_dir = branches_dir / DEFAULT_BRANCH
        main_branch_dir.mkdir(parents=True, exist_ok=True)

        main_content = self._render_main_md(
            project_name=request.project_name,
            project_description=request.project_description,
            goals=request.initial_goals,
            active_branch=DEFAULT_BRANCH,
            timestamp=timestamp,
        )
        self.file_manager.write_text(gcc_dir / MAIN_FILE_NAME, main_content)

        gitignore_updated = self._apply_git_context_policy(
            directory=directory,
            policy=request.git_context_policy,
        )

        config = {
            "version": "0.1.0",
            "project_name": request.project_name,
            "project_description": request.project_description,
            "default_branch": DEFAULT_BRANCH,
            "current_branch": DEFAULT_BRANCH,
            "auto_commit": False,
            "redaction_mode": False,
            "git_context_policy": request.git_context_policy.value,
            "acknowledge_sensitive_data_risk": request.acknowledge_sensitive_data_risk,
            "created_at": timestamp,
            "updated_at": timestamp,
            "activity_log": [],
        }
        self._append_activity(
            config=config,
            action="INIT",
            branch=DEFAULT_BRANCH,
            message="Initialized GCC structure",
            timestamp=timestamp,
        )

        self.file_manager.write_yaml(gcc_dir / CONFIG_FILE_NAME, config)
        self.file_manager.write_text(
            main_branch_dir / COMMIT_FILE_NAME,
            self._render_commit_header(DEFAULT_BRANCH),
        )
        self.file_manager.write_text(
            main_branch_dir / LOG_FILE_NAME,
            self._render_log_header(DEFAULT_BRANCH),
        )
        self.file_manager.write_yaml(
            main_branch_dir / METADATA_FILE_NAME,
            self._new_branch_metadata(
                name=DEFAULT_BRANCH,
                parent=None,
                description="Main development branch",
                tags=[],
                timestamp=timestamp,
            ),
        )

        return InitResponse(
            status="success",
            message=f"GCC initialized in {directory}",
            structure_created=[
                f"{GCC_DIR_NAME}/{MAIN_FILE_NAME}",
                f"{GCC_DIR_NAME}/{CONFIG_FILE_NAME}",
                f"{GCC_DIR_NAME}/{BRANCHES_DIR_NAME}",
                f"{GCC_DIR_NAME}/{BRANCHES_DIR_NAME}/{DEFAULT_BRANCH}/{COMMIT_FILE_NAME}",
                f"{GCC_DIR_NAME}/{BRANCHES_DIR_NAME}/{DEFAULT_BRANCH}/{LOG_FILE_NAME}",
                f"{GCC_DIR_NAME}/{BRANCHES_DIR_NAME}/{DEFAULT_BRANCH}/{METADATA_FILE_NAME}",
            ],
            config={
                "default_branch": config["default_branch"],
                "current_branch": config["current_branch"],
                "auto_commit": config["auto_commit"],
                "git_context_policy": config["git_context_policy"],
            },
            git_context_policy=request.git_context_policy,
            gitignore_updated=gitignore_updated,
            security_notice=SENSITIVE_CONTEXT_NOTICE,
        )

    def commit(self, request: CommitRequest) -> CommitResponse:
        """Persist a commit-like checkpoint for the current GCC branch."""
        gcc_dir, config = self._load_gcc_state(request.directory)
        branch = str(config.get("current_branch", DEFAULT_BRANCH))
        branch_dir = self._require_branch(gcc_dir, branch)

        timestamp = self._now_iso()
        commit_id = self._generate_commit_id()
        commit_entry = self._render_commit_entry(
            timestamp=timestamp,
            commit_id=commit_id,
            request=request,
        )
        log_entry = self._render_log_entry(
            timestamp=timestamp,
            commit_id=commit_id,
            request=request,
        )

        self.file_manager.append_text(branch_dir / COMMIT_FILE_NAME, commit_entry)
        self.file_manager.append_text(branch_dir / LOG_FILE_NAME, log_entry)

        metadata_path = branch_dir / METADATA_FILE_NAME
        metadata = self.file_manager.read_yaml(metadata_path)
        metadata.setdefault("commits", {})
        metadata["commits"]["count"] = int(metadata["commits"].get("count", 0)) + 1
        metadata["commits"]["last"] = timestamp

        metadata.setdefault("files", {})
        metadata["files"]["modified"] = self._unique_preserve_order(
            [*metadata["files"].get("modified", []), *request.files_modified]
        )
        metadata["files"].setdefault("created", [])

        metadata["tags"] = self._unique_preserve_order(
            [*metadata.get("tags", []), *request.tags]
        )

        metadata.setdefault("history", [])
        metadata["history"].append(
            {
                "id": commit_id,
                "type": request.commit_type.value,
                "message": request.message,
                "timestamp": timestamp,
                "tags": request.tags,
                "files_modified": request.files_modified,
                "tests_passed": request.tests_passed,
            }
        )
        self.file_manager.write_yaml(metadata_path, metadata)

        config["updated_at"] = timestamp
        self._append_activity(
            config=config,
            action="COMMIT",
            branch=branch,
            message=request.message,
            timestamp=timestamp,
        )
        self.file_manager.write_yaml(gcc_dir / CONFIG_FILE_NAME, config)
        self._update_main_status(gcc_dir, branch, timestamp)

        return CommitResponse(
            status="success",
            message=f"Milestone saved on branch '{branch}'",
            commit_id=commit_id,
            branch=branch,
            timestamp=timestamp,
            files_updated=[
                str((branch_dir / COMMIT_FILE_NAME).relative_to(gcc_dir.parent)),
                str((branch_dir / LOG_FILE_NAME).relative_to(gcc_dir.parent)),
                str((branch_dir / METADATA_FILE_NAME).relative_to(gcc_dir.parent)),
            ],
        )

    def branch(self, request: BranchRequest) -> BranchResponse:
        """Create a new branch directory and switch active branch."""
        gcc_dir, config = self._load_gcc_state(request.directory)
        branch_name = self._validate_branch_name(request.name)
        new_branch_dir = self._branch_path(gcc_dir, branch_name)
        if new_branch_dir.exists():
            raise GCCError(
                ErrorCode.BRANCH_EXISTS,
                f"Branch '{branch_name}' already exists",
                "Use a different branch name or delete/archive the existing branch.",
            )

        parent_dir = self._require_branch(gcc_dir, request.from_branch, field_name="from_branch")
        timestamp = self._now_iso()
        new_branch_dir.mkdir(parents=True, exist_ok=True)

        parent_metadata = self.file_manager.read_yaml(parent_dir / METADATA_FILE_NAME)
        parent_last_message = ""
        parent_history = parent_metadata.get("history", [])
        if parent_history:
            parent_last_message = str(parent_history[-1].get("message", ""))

        branch_bootstrap_note = (
            f"## [{timestamp}] - Branch created from '{request.from_branch}'\n"
            "\n"
            "**Type**: chore\n"
            "\n"
            "**Summary**:\n"
            f"Created branch '{branch_name}' for: {request.description}\n"
            "\n"
            "**Details**:\n"
            f"- Parent branch: {request.from_branch}\n"
            f"- Context copied: {'yes' if request.copy_context else 'no'}\n"
        )
        if request.copy_context and parent_last_message:
            branch_bootstrap_note += f"- Parent latest milestone: {parent_last_message}\n"
        if request.tags:
            branch_bootstrap_note += f"- Tags: {', '.join(request.tags)}\n"
        branch_bootstrap_note += "\n---\n\n"

        self.file_manager.write_text(
            new_branch_dir / COMMIT_FILE_NAME,
            self._render_commit_header(branch_name) + branch_bootstrap_note,
        )
        self.file_manager.write_text(
            new_branch_dir / LOG_FILE_NAME,
            self._render_log_header(branch_name),
        )
        self.file_manager.write_yaml(
            new_branch_dir / METADATA_FILE_NAME,
            self._new_branch_metadata(
                name=branch_name,
                parent=request.from_branch,
                description=request.description,
                tags=request.tags,
                timestamp=timestamp,
            ),
        )

        config["current_branch"] = branch_name
        config["updated_at"] = timestamp
        self._append_activity(
            config=config,
            action="BRANCH",
            branch=branch_name,
            message=f"Created from {request.from_branch}: {request.description}",
            timestamp=timestamp,
        )
        self.file_manager.write_yaml(gcc_dir / CONFIG_FILE_NAME, config)
        self._update_main_status(gcc_dir, branch_name, timestamp)

        return BranchResponse(
            status="success",
            message=f"Branch '{branch_name}' created",
            branch_name=branch_name,
            branch_path=str(new_branch_dir),
            parent_branch=request.from_branch,
            created_files=[COMMIT_FILE_NAME, LOG_FILE_NAME, METADATA_FILE_NAME],
            context_copied=request.copy_context,
        )

    def merge(self, request: MergeRequest) -> MergeResponse:
        """Record a branch merge and update branch metadata/state."""
        gcc_dir, config = self._load_gcc_state(request.directory)
        if request.source_branch == request.target_branch:
            raise GCCError(
                ErrorCode.MERGE_CONFLICT,
                "Source and target branch must be different",
                "Pick a different target branch for merge.",
            )

        source_dir = self._require_branch(gcc_dir, request.source_branch, field_name="source_branch")
        target_dir = self._require_branch(gcc_dir, request.target_branch, field_name="target_branch")

        source_metadata_path = source_dir / METADATA_FILE_NAME
        target_metadata_path = target_dir / METADATA_FILE_NAME
        source_metadata = self.file_manager.read_yaml(source_metadata_path)
        target_metadata = self.file_manager.read_yaml(target_metadata_path)

        timestamp = self._now_iso()
        commits_merged = int(source_metadata.get("commits", {}).get("count", 0))

        merge_entry = (
            f"## [{timestamp}] - Merge '{request.source_branch}' into '{request.target_branch}'\n"
            "\n"
            "**Type**: chore\n"
            "\n"
            "**Summary**:\n"
            f"{request.summary}\n"
            "\n"
            "**Details**:\n"
            f"- Source branch: {request.source_branch}\n"
            f"- Target branch: {request.target_branch}\n"
            f"- Commits merged: {commits_merged}\n"
            "\n---\n\n"
        )
        self.file_manager.append_text(target_dir / COMMIT_FILE_NAME, merge_entry)

        target_metadata.setdefault("commits", {})
        target_metadata["commits"]["count"] = int(target_metadata["commits"].get("count", 0)) + 1
        target_metadata["commits"]["last"] = timestamp
        target_metadata.setdefault("history", [])
        target_metadata["history"].append(
            {
                "id": self._generate_commit_id(),
                "type": "merge",
                "message": f"Merged {request.source_branch} -> {request.target_branch}",
                "summary": request.summary,
                "timestamp": timestamp,
                "tags": [],
                "merged_commits": commits_merged,
            }
        )
        self.file_manager.write_yaml(target_metadata_path, target_metadata)

        source_metadata.setdefault("branch", {})
        source_metadata["branch"]["integration_status"] = "merged"
        source_metadata["branch"]["status"] = "active" if request.keep_branch else "merged"
        source_metadata["branch"]["merged_into"] = request.target_branch
        source_metadata["branch"]["merged_at"] = timestamp
        self.file_manager.write_yaml(source_metadata_path, source_metadata)

        if str(config.get("current_branch", DEFAULT_BRANCH)) == request.source_branch:
            config["current_branch"] = request.target_branch
        config["updated_at"] = timestamp
        self._append_activity(
            config=config,
            action="MERGE",
            branch=request.target_branch,
            message=f"{request.source_branch} -> {request.target_branch}: {request.summary}",
            timestamp=timestamp,
        )
        self.file_manager.write_yaml(gcc_dir / CONFIG_FILE_NAME, config)
        self._update_main_status(gcc_dir, str(config.get("current_branch", DEFAULT_BRANCH)), timestamp)
        if request.update_roadmap:
            self._append_main_merge_note(
                gcc_dir=gcc_dir,
                source_branch=request.source_branch,
                target_branch=request.target_branch,
                summary=request.summary,
                timestamp=timestamp,
            )

        return MergeResponse(
            status="success",
            message=f"Branch '{request.source_branch}' merged into '{request.target_branch}'",
            merged_from=request.source_branch,
            merged_into=request.target_branch,
            commits_merged=commits_merged,
            main_updated=request.update_roadmap,
            branch_archived=not request.keep_branch,
            source_branch_status=source_metadata["branch"]["status"],
            integration_status=source_metadata["branch"]["integration_status"],
            timestamp=timestamp,
        )

    def get_context(self, request: ContextRequest) -> ContextResponse:
        """Return filtered context snapshots for selected branches."""
        gcc_dir, config = self._load_gcc_state(request.directory)
        all_branch_dirs = sorted((gcc_dir / BRANCHES_DIR_NAME).iterdir(), key=lambda item: item.name)
        all_branch_names = [item.name for item in all_branch_dirs if item.is_dir()]

        selected_branches = request.scope or all_branch_names
        missing = [name for name in selected_branches if name not in all_branch_names]
        if missing:
            raise GCCError(
                ErrorCode.BRANCH_NOT_FOUND,
                "One or more branches were not found",
                "Check branch names with gcc_status or gcc_context scope.",
                {"missing_branches": missing},
            )

        branches_payload: list[dict[str, Any]] = []
        active_count = 0
        archived_count = 0

        for branch_name in selected_branches:
            branch_dir = gcc_dir / BRANCHES_DIR_NAME / branch_name
            metadata = self.file_manager.read_yaml(branch_dir / METADATA_FILE_NAME)
            branch_info = metadata.get("branch", {})
            history = metadata.get("history", [])
            filtered_history = self._filter_history(
                history=history,
                since=request.since,
                tags=request.tags,
            )

            has_filter = bool(request.since or request.tags)
            if has_filter and not filtered_history:
                continue

            status = str(branch_info.get("status", "active"))
            is_active = status == "active"
            if is_active:
                active_count += 1
            else:
                archived_count += 1

            item: dict[str, Any] = {
                "name": branch_name,
                "status": status,
                "integration_status": str(branch_info.get("integration_status", "open")),
                "description": str(branch_info.get("description", "")),
                "parent": branch_info.get("parent"),
                "commit_count": int(metadata.get("commits", {}).get("count", 0)),
                "last_commit": metadata.get("commits", {}).get("last"),
                "tags": metadata.get("tags", []),
            }

            if request.level.value in {"detailed", "full"}:
                item["commits"] = filtered_history

            if request.level.value == "full":
                item["commit_md"] = self.file_manager.read_text(branch_dir / COMMIT_FILE_NAME)
                item["log_md"] = self.file_manager.read_text(branch_dir / LOG_FILE_NAME)

            branches_payload.append(item)

        generated_at = self._now_iso()
        data: dict[str, Any] = {
            "project_name": str(config.get("project_name", "")),
            "current_branch": str(config.get("current_branch", DEFAULT_BRANCH)),
            "level": request.level.value,
            "branches": branches_payload,
            "summary": {
                "active_branches": active_count,
                "archived_branches": archived_count,
                "returned_branches": len(branches_payload),
            },
            "filters": {
                "since": request.since.isoformat() if request.since else "",
                "tags": request.tags,
                "scope": selected_branches,
            },
        }

        redaction_enabled = bool(request.redact_sensitive or config.get("redaction_mode", False))
        if redaction_enabled:
            data = self._redact_payload(data)

        rendered = ""
        if request.format == ContextFormat.MARKDOWN:
            rendered = self._render_context_markdown(data)
        elif request.format == ContextFormat.YAML:
            rendered = yaml.safe_dump(data, sort_keys=False, allow_unicode=False)

        return ContextResponse(
            status="success",
            message="Context retrieved",
            level=request.level,
            format=request.format,
            generated_at=generated_at,
            redaction_applied=redaction_enabled,
            security_notice=REDACTION_NOTICE,
            data=data,
            rendered=rendered,
        )

    def get_status(self, request: StatusRequest) -> StatusResponse:
        """Return current project status and recent activity."""
        gcc_dir, config = self._load_gcc_state(request.directory)
        branches_root = gcc_dir / BRANCHES_DIR_NAME
        if not branches_root.exists():
            raise GCCError(
                ErrorCode.GCC_NOT_FOUND,
                f"No branches directory found under {gcc_dir}",
                "Run gcc_init again to repair the structure.",
            )

        active = 0
        archived = 0
        current_branch = str(config.get("current_branch", DEFAULT_BRANCH))
        last_commit_message = ""
        last_commit_id = ""

        for branch_dir in branches_root.iterdir():
            if not branch_dir.is_dir():
                continue
            metadata = self.file_manager.read_yaml(branch_dir / METADATA_FILE_NAME)
            status = str(metadata.get("branch", {}).get("status", "active"))
            if status == "active":
                active += 1
            else:
                archived += 1

            if branch_dir.name == current_branch:
                history = metadata.get("history", [])
                if history:
                    last = history[-1]
                    last_commit_message = str(last.get("message", ""))
                    last_commit_id = str(last.get("id", ""))

        activity = list(config.get("activity_log", []))
        recent_activity = list(reversed(activity[-5:]))

        return StatusResponse(
            status="success",
            message="Status retrieved",
            project_name=str(config.get("project_name", "")),
            current_branch=current_branch,
            last_commit_id=last_commit_id,
            last_commit_message=last_commit_message,
            active_branches=active,
            archived_branches=archived,
            recent_activity=recent_activity,
        )

    def get_config(self, directory: str) -> dict[str, Any]:
        """Return raw GCC configuration for the target directory."""
        _, config = self._load_gcc_state(directory)
        return config

    def set_config(self, directory: str, key: str, value: Any) -> dict[str, Any]:
        """Set a mutable config key and persist it."""
        gcc_dir, config = self._load_gcc_state(directory)
        mutable_keys = {
            "default_branch",
            "auto_commit",
            "editor",
            "log_level",
            "max_commits",
            "context_cache_ttl",
            "current_branch",
            "redaction_mode",
        }
        if key not in mutable_keys:
            raise GCCError(
                ErrorCode.INVALID_INPUT,
                f"Unsupported config key '{key}'",
                f"Use one of: {', '.join(sorted(mutable_keys))}",
            )

        if key in {"max_commits", "context_cache_ttl"}:
            try:
                value = int(value)
            except (TypeError, ValueError) as exc:
                raise GCCError(
                    ErrorCode.INVALID_INPUT,
                    f"Config key '{key}' requires an integer value",
                    "Provide a numeric value.",
                ) from exc

        if key in {"auto_commit", "redaction_mode"}:
            value = self._coerce_bool(value)

        if key in {"default_branch", "current_branch"}:
            value = str(value)
            self._require_branch(gcc_dir, value)

        if key == "current_branch":
            self.checkout_branch(directory, value)
            _, updated_config = self._load_gcc_state(directory)
            return updated_config

        config[key] = value
        config["updated_at"] = self._now_iso()
        self.file_manager.write_yaml(gcc_dir / CONFIG_FILE_NAME, config)
        return config

    def checkout_branch(self, directory: str, branch_name: str) -> dict[str, Any]:
        """Switch active branch in GCC configuration."""
        gcc_dir, config = self._load_gcc_state(directory)
        self._require_branch(gcc_dir, branch_name)
        previous = str(config.get("current_branch", DEFAULT_BRANCH))
        config["current_branch"] = branch_name
        timestamp = self._now_iso()
        config["updated_at"] = timestamp
        self._append_activity(
            config=config,
            action="CHECKOUT",
            branch=branch_name,
            message=f"Switched from {previous} to {branch_name}",
            timestamp=timestamp,
        )
        self.file_manager.write_yaml(gcc_dir / CONFIG_FILE_NAME, config)
        self._update_main_status(gcc_dir, branch_name, timestamp)
        return {
            "status": "success",
            "message": f"Switched to branch '{branch_name}'",
            "previous_branch": previous,
            "current_branch": branch_name,
        }

    def list_branches(
        self,
        directory: str,
        active_only: bool = False,
        archived_only: bool = False,
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """List branches with filters."""
        if active_only and archived_only:
            raise GCCError(
                ErrorCode.INVALID_INPUT,
                "Cannot combine active-only and archived-only filters",
                "Pick exactly one branch-state filter or none.",
            )

        gcc_dir, config = self._load_gcc_state(directory)
        tags_filter = {tag.lower() for tag in (tags or [])}
        current_branch = str(config.get("current_branch", DEFAULT_BRANCH))
        branches: list[dict[str, Any]] = []

        for branch_dir in sorted((gcc_dir / BRANCHES_DIR_NAME).iterdir(), key=lambda x: x.name):
            if not branch_dir.is_dir():
                continue
            metadata = self.file_manager.read_yaml(branch_dir / METADATA_FILE_NAME)
            branch_info = metadata.get("branch", {})
            status = str(branch_info.get("status", "active"))
            branch_tags = [str(tag) for tag in metadata.get("tags", [])]
            branch_tags_lower = {tag.lower() for tag in branch_tags}

            if active_only and status != "active":
                continue
            if archived_only and status == "active":
                continue
            if tags_filter and not branch_tags_lower.intersection(tags_filter):
                continue

            branches.append(
                {
                    "name": branch_dir.name,
                    "status": status,
                    "integration_status": str(branch_info.get("integration_status", "open")),
                    "description": str(branch_info.get("description", "")),
                    "parent": branch_info.get("parent"),
                    "current": branch_dir.name == current_branch,
                    "tags": branch_tags,
                    "commit_count": int(metadata.get("commits", {}).get("count", 0)),
                    "last_commit": metadata.get("commits", {}).get("last"),
                }
            )

        return {
            "status": "success",
            "message": "Branches listed",
            "current_branch": current_branch,
            "count": len(branches),
            "branches": branches,
        }

    def get_log(
        self,
        directory: str,
        branch_name: str | None = None,
        limit: int | None = None,
        since: date | None = None,
        commit_type: str | None = None,
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Return commit history entries for a branch."""
        gcc_dir, config = self._load_gcc_state(directory)
        branch = branch_name or str(config.get("current_branch", DEFAULT_BRANCH))
        branch_dir = self._require_branch(gcc_dir, branch)
        metadata = self.file_manager.read_yaml(branch_dir / METADATA_FILE_NAME)
        history = list(metadata.get("history", []))

        if commit_type:
            history = [entry for entry in history if str(entry.get("type", "")) == commit_type]
        history = self._filter_history(history=history, since=since, tags=tags or [])
        if limit is not None and limit > 0:
            history = history[-limit:]

        return {
            "status": "success",
            "message": "Log retrieved",
            "branch": branch,
            "count": len(history),
            "entries": history,
        }

    def delete_branch(
        self,
        directory: str,
        branch_name: str,
        force: bool = False,
        archive: bool = False,
    ) -> dict[str, Any]:
        """Archive or delete a branch."""
        if not branch_name:
            raise GCCError(
                ErrorCode.INVALID_INPUT,
                "Branch name is required",
                "Provide a branch name.",
            )
        branch_name = self._validate_branch_name(branch_name)

        gcc_dir, config = self._load_gcc_state(directory)
        if branch_name == DEFAULT_BRANCH:
            raise GCCError(
                ErrorCode.INVALID_INPUT,
                "Cannot delete the default branch",
                "Use merge/archive workflows instead.",
            )

        current = str(config.get("current_branch", DEFAULT_BRANCH))
        if branch_name == current:
            raise GCCError(
                ErrorCode.INVALID_INPUT,
                f"Cannot delete current branch '{branch_name}'",
                "Checkout a different branch first.",
            )

        branch_dir = self._require_branch(gcc_dir, branch_name)
        metadata_path = branch_dir / METADATA_FILE_NAME
        metadata = self.file_manager.read_yaml(metadata_path)
        timestamp = self._now_iso()

        if archive:
            metadata.setdefault("branch", {})
            metadata["branch"]["status"] = "abandoned"
            metadata["branch"]["archived_at"] = timestamp
            self.file_manager.write_yaml(metadata_path, metadata)
            result_message = f"Branch '{branch_name}' archived"
        elif force:
            shutil.rmtree(branch_dir)
            result_message = f"Branch '{branch_name}' deleted"
        else:
            raise GCCError(
                ErrorCode.INVALID_INPUT,
                f"Branch '{branch_name}' was not removed",
                "Use --archive or --force for delete operation.",
            )

        self._append_activity(
            config=config,
            action="DELETE" if force else "ARCHIVE",
            branch=branch_name,
            message=result_message,
            timestamp=timestamp,
        )
        config["updated_at"] = timestamp
        self.file_manager.write_yaml(gcc_dir / CONFIG_FILE_NAME, config)

        return {
            "status": "success",
            "message": result_message,
            "branch": branch_name,
            "mode": "force-delete" if force else "archive",
        }

    def scaffold_skill(
        self,
        directory: str,
        template: str = "codex",
        force: bool = False,
    ) -> dict[str, Any]:
        """Create a SKILL.md scaffold in the target directory."""
        target_directory = self._resolve_existing_directory(directory)
        normalized_template = str(template).strip().lower()
        if normalized_template not in SKILL_TEMPLATE_CHOICES:
            choices = ", ".join(sorted(SKILL_TEMPLATE_CHOICES))
            raise GCCError(
                ErrorCode.INVALID_INPUT,
                f"Unsupported skill template '{template}'",
                f"Use one of: {choices}.",
            )

        skill_path = target_directory / "SKILL.md"
        existed = skill_path.exists()
        if existed and not force:
            raise GCCError(
                ErrorCode.INVALID_INPUT,
                f"SKILL.md already exists in {target_directory}",
                "Use --force to overwrite or edit the existing SKILL.md file.",
            )

        project_name, project_description = self._resolve_scaffold_project_metadata(target_directory)
        rendered = self._render_skill_template(
            template=normalized_template,
            project_name=project_name,
            project_description=project_description,
        )
        self.file_manager.write_text(skill_path, rendered)

        action = "overwritten" if existed else "created"
        return {
            "status": "success",
            "message": f"SKILL.md {action} using '{normalized_template}' template",
            "path": str(skill_path),
            "template": normalized_template,
            "overwritten": existed,
        }

    def resolve_directory(self, directory: str) -> dict[str, str]:
        """Resolve a request directory into the effective runtime path."""
        requested, resolved = self._resolve_existing_directory_with_metadata(directory)
        return {
            "directory_requested": str(requested),
            "directory_resolved": str(resolved),
        }

    def _resolve_existing_directory(self, directory: str) -> Path:
        """Resolve and validate a repository directory path."""
        _, resolved = self._resolve_existing_directory_with_metadata(directory)
        return resolved

    def _resolve_existing_directory_with_metadata(self, directory: str) -> tuple[Path, Path]:
        """Resolve a directory path, applying optional host/container path mapping."""
        requested = self._normalize_runtime_path(directory)
        candidates = self._build_directory_candidates(requested)
        blocked_paths: list[Path] = []

        for candidate in candidates:
            if not candidate.exists() or not candidate.is_dir():
                continue
            if self._allowed_roots and not self._is_allowed_directory(candidate):
                blocked_paths.append(candidate)
                continue
            return requested, candidate

        details: dict[str, Any] = {
            "requested_directory": str(requested),
            "candidate_paths": [str(path) for path in candidates],
        }
        if self._path_mappings:
            details["path_mappings"] = [
                {"from": str(source), "to": str(target)}
                for source, target in self._path_mappings
            ]

        if blocked_paths:
            details["blocked_paths"] = [str(path) for path in blocked_paths]
            details["allowed_roots"] = [str(root) for root in self._allowed_roots]
            raise GCCError(
                ErrorCode.INVALID_DIRECTORY,
                f"Directory path is outside configured allowed roots: {directory}",
                "Use a path under GCC_MCP_ALLOWED_ROOTS or adjust the allowlist.",
                details=details,
            )

        suggestion = "Provide an existing directory path."
        if len(candidates) > 1:
            suggestion = (
                "Provide an existing directory path or configure GCC_MCP_PATH_MAP to "
                "translate host paths to runtime paths."
            )
        raise GCCError(
            ErrorCode.INVALID_DIRECTORY,
            f"Invalid directory path: {directory}",
            suggestion,
            details=details,
        )

    def _build_directory_candidates(self, requested: Path) -> list[Path]:
        """Build candidate directories from direct and mapped path variants."""
        candidates: list[Path] = [requested]
        for source_root, target_root in self._path_mappings:
            try:
                suffix = requested.relative_to(source_root)
            except ValueError:
                continue
            mapped = (target_root / suffix).resolve(strict=False)
            if mapped not in candidates:
                candidates.append(mapped)
        return candidates

    def _is_allowed_directory(self, path: Path) -> bool:
        """Return whether a path is within configured allowed roots."""
        for root in self._allowed_roots:
            try:
                path.relative_to(root)
                return True
            except ValueError:
                continue
        return False

    def _normalize_runtime_path(self, value: str) -> Path:
        """Normalize user-provided runtime paths for stable resolution."""
        normalized = str(value).strip() or "."
        return Path(normalized).expanduser().resolve(strict=False)

    def _normalize_path_mappings(
        self,
        mappings: list[tuple[str, str]] | tuple[tuple[str, str], ...],
    ) -> tuple[tuple[Path, Path], ...]:
        """Normalize and sort path mappings for longest-prefix matching."""
        normalized: list[tuple[Path, Path]] = []
        seen: set[tuple[str, str]] = set()

        for source_raw, target_raw in mappings:
            source = self._normalize_absolute_config_path(source_raw, field_name="path_mappings.from")
            target = self._normalize_absolute_config_path(target_raw, field_name="path_mappings.to")
            key = (str(source), str(target))
            if key in seen:
                continue
            seen.add(key)
            normalized.append((source, target))

        normalized.sort(key=lambda item: len(item[0].parts), reverse=True)
        return tuple(normalized)

    def _normalize_allowed_roots(
        self,
        roots: list[str] | tuple[str, ...],
    ) -> tuple[Path, ...]:
        """Normalize allowed root paths with duplicate suppression."""
        normalized: list[Path] = []
        seen: set[str] = set()
        for root_raw in roots:
            root = self._normalize_absolute_config_path(root_raw, field_name="allowed_roots")
            key = str(root)
            if key in seen:
                continue
            seen.add(key)
            normalized.append(root)

        normalized.sort(key=lambda item: len(item.parts), reverse=True)
        return tuple(normalized)

    def _normalize_absolute_config_path(self, value: str, field_name: str) -> Path:
        """Normalize absolute configuration path values."""
        normalized = str(value).strip()
        if not normalized:
            raise ValueError(f"{field_name} must be a non-empty absolute path.")
        path = Path(normalized).expanduser()
        if not path.is_absolute():
            raise ValueError(f"{field_name} must be an absolute path: {normalized}")
        return path.resolve(strict=False)

    def _resolve_scaffold_project_metadata(self, directory: Path) -> tuple[str, str]:
        """Load project metadata for SKILL.md scaffolding."""
        fallback_name = directory.name or "project"
        project_name = fallback_name
        project_description = ""

        config_path = directory / GCC_DIR_NAME / CONFIG_FILE_NAME
        if config_path.exists():
            config = self.file_manager.read_yaml(config_path)
            configured_name = str(config.get("project_name", "")).strip()
            configured_description = str(config.get("project_description", "")).strip()
            if configured_name:
                project_name = configured_name
            if configured_description:
                project_description = configured_description

        return project_name, project_description

    def _load_gcc_state(self, directory: str) -> tuple[Path, dict[str, Any]]:
        """Load `.GCC` root path and validated configuration data."""
        root = self._resolve_existing_directory(directory)
        gcc_dir = root / GCC_DIR_NAME
        if not gcc_dir.exists():
            raise GCCError(
                ErrorCode.GCC_NOT_FOUND,
                f".GCC directory not found in {root}",
                "Initialize GCC first using gcc_init.",
            )
        config_path = gcc_dir / CONFIG_FILE_NAME
        config = self.file_manager.read_yaml(config_path)
        if not config:
            raise GCCError(
                ErrorCode.GCC_NOT_FOUND,
                f"Missing or invalid GCC configuration: {config_path}",
                "Re-run gcc_init or restore .gcc-config.yaml.",
            )
        return gcc_dir, config

    def _require_branch(
        self,
        gcc_dir: Path,
        branch_name: str,
        field_name: str = "branch",
    ) -> Path:
        """Validate branch naming/path safety and ensure branch exists."""
        normalized_name = self._validate_branch_name(branch_name, field_name=field_name)
        branch_dir = self._branch_path(gcc_dir, normalized_name, field_name=field_name)
        if not branch_dir.exists() or not branch_dir.is_dir():
            raise GCCError(
                ErrorCode.BRANCH_NOT_FOUND,
                f"Branch '{normalized_name}' does not exist",
                "Create the branch first or choose an existing branch.",
                {"branch": normalized_name},
            )
        return branch_dir

    def _branch_path(
        self,
        gcc_dir: Path,
        branch_name: str,
        field_name: str = "branch",
    ) -> Path:
        """Build a normalized branch path constrained to the branches root."""
        normalized_name = self._validate_branch_name(branch_name, field_name=field_name)
        branches_root = gcc_dir / BRANCHES_DIR_NAME
        branches_root_resolved = branches_root.resolve()
        branch_dir = (branches_root / normalized_name).resolve()
        try:
            branch_dir.relative_to(branches_root_resolved)
        except ValueError as exc:
            raise GCCError(
                ErrorCode.INVALID_BRANCH_NAME,
                f"Invalid {field_name} name '{normalized_name}'",
                "Use lowercase letters, numbers, and hyphens only.",
            ) from exc
        return branch_dir

    def _validate_branch_name(self, branch_name: str, field_name: str = "branch") -> str:
        """Validate branch names against the strict lowercase-hyphen policy."""
        name = str(branch_name).strip()
        if not name or not BRANCH_NAME_PATTERN.fullmatch(name):
            raise GCCError(
                ErrorCode.INVALID_BRANCH_NAME,
                f"Invalid {field_name} name '{branch_name}'",
                "Use lowercase letters, numbers, and hyphens only.",
            )
        return name

    def _slugify_skill_name(self, value: str) -> str:
        """Convert arbitrary project names into skill-friendly slugs."""
        slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
        if not slug:
            return "project-context"
        return slug[:64].strip("-") or "project-context"

    def _render_skill_template(
        self,
        template: str,
        project_name: str,
        project_description: str,
    ) -> str:
        """Render SKILL.md scaffolds for supported template variants."""
        skill_slug = self._slugify_skill_name(project_name)
        summary = project_description or "No project description provided."

        if template == "codex":
            return (
                f"---\n"
                f"name: {skill_slug}-context\n"
                "description: Use this skill to capture and retrieve durable project context "
                "with GCC across Codex sessions.\n"
                "---\n\n"
                f"# {project_name} Context Skill\n\n"
                "## Project Summary\n\n"
                f"{summary}\n\n"
                "## Trigger Conditions\n\n"
                "- start or resume work in this project\n"
                "- record meaningful milestone/decision changes\n"
                "- store user preferences (coding style, review style, communication style)\n"
                "- compare strategies via branches and merge the chosen approach\n\n"
                "## Memory Workflow\n\n"
                "1. Restore context: `gcc-cli context --level summary`\n"
                "2. If needed, create branch: `gcc-cli branch ...`\n"
                "3. Checkpoint meaningful progress: `gcc-cli commit ...`\n"
                "4. Persist preference/style updates with `tags=preferences,...`\n"
                "5. End sessions with a concise commit containing next actions and risks\n\n"
                "## Retrieval Hints\n\n"
                "- use `scope`, `since`, and `tags` filters for focused recalls\n"
                "- query `level=detailed` when milestone summaries are required\n"
                "- query `level=full` only when deep OTA traces are necessary\n"
            )

        return (
            f"---\n"
            f"name: {skill_slug}-memory\n"
            "description: Structured memory workflow for long-running AI-agent tasks using "
            "Git Context Controller.\n"
            "---\n\n"
            f"# {project_name} Agent Memory Skill\n\n"
            "## Project Summary\n\n"
            f"{summary}\n\n"
            "## Purpose\n\n"
            "Use GCC to preserve durable context between sessions, including key milestones,\n"
            "decisions, and user preferences.\n\n"
            "## Standard Flow\n\n"
            "1. Restore context (`status`/`context`)\n"
            "2. Branch when evaluating alternatives\n"
            "3. Commit meaningful outcomes\n"
            "4. Merge successful branches\n"
            "5. Capture user preference updates explicitly with tags\n\n"
            "## Notes\n\n"
            "- keep entries concise, decision-oriented, and searchable\n"
            "- avoid logging secrets in plain text\n"
            "- keep `.GCC` git-tracking policy explicit per repository\n"
        )

    def _new_branch_metadata(
        self,
        name: str,
        parent: str | None,
        description: str,
        tags: list[str],
        timestamp: str,
    ) -> dict[str, Any]:
        """Create initial metadata payload for a newly created branch."""
        return {
            "branch": {
                "name": name,
                "created": timestamp,
                "parent": parent,
                "status": "active",
                "integration_status": "open",
                "description": description,
            },
            "commits": {"count": 0, "last": None},
            "files": {"modified": [], "created": []},
            "tags": tags,
            "history": [],
        }

    def _render_main_md(
        self,
        project_name: str,
        project_description: str,
        goals: list[str],
        active_branch: str,
        timestamp: str,
    ) -> str:
        """Render initial `main.md` content for a GCC project."""
        rendered_goals = "\n".join(f"- [ ] {goal}" for goal in goals) or "- [ ] Define initial goals"
        description = project_description or "No project description provided."
        return (
            f"# Project: {project_name}\n\n"
            "## Overview\n"
            f"{description}\n\n"
            "## Goals\n"
            f"{rendered_goals}\n\n"
            "## Current Status\n"
            f"**Active Branch**: {active_branch}\n"
            f"**Last Updated**: {timestamp[:10]}\n"
            "**Progress**: 0%\n\n"
            "## Roadmap\n"
            "### Phase 1: Foundation\n"
            "- [ ] Initialize project context\n"
            "- [ ] Record first milestone\n\n"
            "## Branches\n"
            f"### {active_branch}\n"
            "Status: Active\n"
            "Purpose: Primary implementation\n"
            "Last commit: none\n"
        )

    def _render_commit_header(self, branch_name: str) -> str:
        """Render commit file header for a branch."""
        return f"# Commit History: {branch_name}\n\n"

    def _render_log_header(self, branch_name: str) -> str:
        """Render execution log header for a branch."""
        return f"# Execution Log: {branch_name}\n\n"

    def _render_commit_entry(self, timestamp: str, commit_id: str, request: CommitRequest) -> str:
        """Render a markdown commit entry."""
        details = request.details or ["No additional details provided."]
        files = request.files_modified or ["No files listed."]
        tags = request.tags or ["untagged"]
        notes = request.notes or "None"

        details_block = "\n".join(f"- {detail}" for detail in details)
        files_block = "\n".join(f"- `{path}`" for path in files)
        tags_block = "\n".join(f"- {tag}" for tag in tags)
        tests_line = "[x] Tests passed" if request.tests_passed else "[ ] Tests failed"

        return (
            f"## [{timestamp}] - {request.message}\n\n"
            f"**ID**: {commit_id}\n\n"
            f"**Type**: {request.commit_type.value}\n\n"
            "**Summary**:\n"
            f"{request.message}\n\n"
            "**Details**:\n"
            f"{details_block}\n\n"
            "**Files Modified**:\n"
            f"{files_block}\n\n"
            "**Tests**:\n"
            f"- {tests_line}\n\n"
            "**Notes**:\n"
            f"{notes}\n\n"
            "**Tags**:\n"
            f"{tags_block}\n\n"
            "---\n\n"
        )

    def _render_log_entry(self, timestamp: str, commit_id: str, request: CommitRequest) -> str:
        """Render an OTA-style execution log entry."""
        observation = request.ota_log.observation if request.ota_log else "No observation provided."
        thought = request.ota_log.thought if request.ota_log else "No thought provided."
        action = request.ota_log.action if request.ota_log else request.message
        result = request.ota_log.result if request.ota_log else "Milestone recorded."
        files_touched = ", ".join(request.files_modified) if request.files_modified else "None listed"
        error_count = "0" if request.tests_passed else "1+"

        return (
            f"## [{timestamp}] - {commit_id}\n\n"
            "**Observation**:\n"
            f"{observation}\n\n"
            "**Thought**:\n"
            f"{thought}\n\n"
            "**Action**:\n"
            f"{action}\n\n"
            "**Result**:\n"
            f"{result}\n\n"
            "**Metadata**:\n"
            "- Duration: n/a\n"
            f"- Files touched: {files_touched}\n"
            f"- Error count: {error_count}\n\n"
            "---\n\n"
        )

    def _update_main_status(self, gcc_dir: Path, current_branch: str, timestamp: str) -> None:
        """Update active branch and date markers in `main.md`."""
        main_path = gcc_dir / MAIN_FILE_NAME
        current_content = self.file_manager.read_text(main_path)
        if not current_content:
            return
        updated = re.sub(
            r"\*\*Active Branch\*\*:\s*.*",
            f"**Active Branch**: {current_branch}",
            current_content,
        )
        updated = re.sub(
            r"\*\*Last Updated\*\*:\s*.*",
            f"**Last Updated**: {timestamp[:10]}",
            updated,
        )
        self.file_manager.write_text(main_path, updated)

    def _append_main_merge_note(
        self,
        gcc_dir: Path,
        source_branch: str,
        target_branch: str,
        summary: str,
        timestamp: str,
    ) -> None:
        """Append merge notes to `main.md` for roadmap visibility."""
        main_path = gcc_dir / MAIN_FILE_NAME
        content = self.file_manager.read_text(main_path)
        if not content:
            return
        merge_note = (
            "\n## Merge Notes\n"
            f"- [{timestamp}] {source_branch} -> {target_branch}: {summary}\n"
        )
        if "## Merge Notes" in content:
            content += f"- [{timestamp}] {source_branch} -> {target_branch}: {summary}\n"
        else:
            content += merge_note
        self.file_manager.write_text(main_path, content)

    def _append_activity(
        self,
        config: dict[str, Any],
        action: str,
        branch: str,
        message: str,
        timestamp: str,
    ) -> None:
        """Append a bounded activity entry to configuration history."""
        activity = config.setdefault("activity_log", [])
        activity.append(
            {
                "timestamp": timestamp,
                "action": action,
                "branch": branch,
                "message": message,
            }
        )
        if len(activity) > MAX_ACTIVITY_ENTRIES:
            config["activity_log"] = activity[-MAX_ACTIVITY_ENTRIES:]

    def _apply_git_context_policy(
        self,
        directory: Path,
        policy: GitContextPolicy,
    ) -> bool:
        """Apply `.GCC` git-tracking policy in `.gitignore`."""
        gitignore_path = directory / ".gitignore"
        normalized_entries = {".GCC/", "/.GCC/"}

        existing_lines: list[str] = []
        if gitignore_path.exists():
            existing_lines = gitignore_path.read_text(encoding="utf-8").splitlines()

        existing_set = set(existing_lines)
        updated = False

        if policy == GitContextPolicy.IGNORE:
            if ".GCC/" not in existing_set and "/.GCC/" not in existing_set:
                if existing_lines and existing_lines[-1].strip():
                    existing_lines.append("")
                existing_lines.append("# GCC context directory (contains potentially sensitive data)")
                existing_lines.append(".GCC/")
                updated = True
        else:
            filtered_lines = [line for line in existing_lines if line.strip() not in normalized_entries]
            if filtered_lines != existing_lines:
                existing_lines = filtered_lines
                updated = True

        if updated:
            content = "\n".join(existing_lines).rstrip() + "\n"
            self.file_manager.write_text(gitignore_path, content)

        return updated

    def _coerce_bool(self, value: Any) -> bool:
        """Parse common string/number representations into booleans."""
        if isinstance(value, bool):
            return value
        normalized = str(value).strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
        raise GCCError(
            ErrorCode.INVALID_INPUT,
            f"Cannot parse boolean value '{value}'",
            "Use true/false values.",
        )

    def _redact_payload(self, payload: Any) -> Any:
        """Recursively redact potentially sensitive strings in payload data."""
        if isinstance(payload, dict):
            return {key: self._redact_payload(value) for key, value in payload.items()}
        if isinstance(payload, list):
            return [self._redact_payload(item) for item in payload]
        if isinstance(payload, str):
            return self._redact_string(payload)
        return payload

    def _redact_string(self, value: str) -> str:
        """Apply conservative string-level redaction heuristics."""
        redacted = value
        # Common key=value secret patterns.
        redacted = re.sub(
            r"(?i)\b(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*([^\s,;]+)",
            r"\1=[REDACTED]",
            redacted,
        )
        # Bearer tokens.
        redacted = re.sub(r"(?i)\bbearer\s+[a-z0-9\-\._~\+\/]+=*", "Bearer [REDACTED]", redacted)
        # High-entropy long literals (simple heuristic).
        redacted = re.sub(r"\b[A-Za-z0-9_\-]{24,}\b", "[REDACTED]", redacted)
        # Absolute filesystem paths.
        redacted = re.sub(r"(?<![A-Za-z0-9])/(?:[^/\s]+/)+[^/\s]*", "/[REDACTED_PATH]", redacted)
        return redacted

    def _generate_commit_id(self) -> str:
        """Generate a timestamp-based commit identifier."""
        return f"gcc-commit-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')}"

    def _now_iso(self) -> str:
        """Return current UTC timestamp in ISO-8601 format."""
        return datetime.now(timezone.utc).isoformat()

    def _unique_preserve_order(self, values: list[str]) -> list[str]:
        """Remove duplicates while preserving original order."""
        seen: set[str] = set()
        result: list[str] = []
        for value in values:
            if value not in seen:
                seen.add(value)
                result.append(value)
        return result

    def _filter_history(
        self,
        history: list[dict[str, Any]],
        since: date | None,
        tags: list[str],
    ) -> list[dict[str, Any]]:
        """Filter history entries by date and optional tag intersection."""
        tag_filter = {tag.lower() for tag in tags}
        filtered: list[dict[str, Any]] = []
        for entry in history:
            timestamp = str(entry.get("timestamp", ""))
            entry_date: date | None = None
            if timestamp:
                parsed = self._parse_iso_datetime(timestamp)
                if parsed:
                    entry_date = parsed.date()

            if since and entry_date and entry_date < since:
                continue
            if since and entry_date is None:
                continue

            if tag_filter:
                entry_tags = {str(tag).lower() for tag in entry.get("tags", [])}
                if not entry_tags.intersection(tag_filter):
                    continue

            filtered.append(entry)
        return filtered

    def _parse_iso_datetime(self, value: str) -> datetime | None:
        """Parse an ISO-8601 datetime string and normalize `Z` suffix."""
        normalized = value.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(normalized)
        except ValueError:
            return None

    def _render_context_markdown(self, data: dict[str, Any]) -> str:
        """Render context payload as readable markdown text."""
        lines = [
            f"Project: {data.get('project_name', '')}",
            f"Current Branch: {data.get('current_branch', DEFAULT_BRANCH)}",
            f"Level: {data.get('level', 'summary')}",
            "",
            "Branches:",
        ]
        branches = data.get("branches", [])
        if not branches:
            lines.append("- No branches matched the selected filters.")
        for branch in branches:
            lines.append(
                f"- {branch.get('name')} [{branch.get('status')}] "
                f"({branch.get('commit_count', 0)} commits)"
            )
            if "commits" in branch:
                commits = branch.get("commits", [])
                if not commits:
                    lines.append("  - No commits matched the filters.")
                for commit in commits:
                    lines.append(
                        f"  - [{commit.get('timestamp', '')}] "
                        f"{commit.get('type', 'event')}: {commit.get('message', '')}"
                    )
        return "\n".join(lines)
