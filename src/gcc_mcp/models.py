"""Pydantic models for GCC tool inputs and outputs."""

from __future__ import annotations

from datetime import date
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class CommitType(str, Enum):
    FEATURE = "feature"
    BUGFIX = "bugfix"
    REFACTOR = "refactor"
    TEST = "test"
    DOCS = "docs"
    CHORE = "chore"


class ContextLevel(str, Enum):
    SUMMARY = "summary"
    DETAILED = "detailed"
    FULL = "full"


class ContextFormat(str, Enum):
    MARKDOWN = "markdown"
    JSON = "json"
    YAML = "yaml"


class GitContextPolicy(str, Enum):
    IGNORE = "ignore"
    TRACK = "track"


class OtaLog(BaseModel):
    observation: str = ""
    thought: str = ""
    action: str = ""
    result: str = ""


class InitRequest(BaseModel):
    directory: str = Field(..., description="Path to directory where .GCC should be initialized")
    project_name: str = Field(..., min_length=1, max_length=100)
    project_description: str = Field(default="", max_length=500)
    initial_goals: list[str] = Field(default_factory=list, max_length=20)
    git_context_policy: GitContextPolicy = GitContextPolicy.IGNORE
    acknowledge_sensitive_data_risk: bool = False

    @field_validator("project_name")
    @classmethod
    def _project_name_not_blank(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("project_name must not be blank")
        return stripped

    @field_validator("acknowledge_sensitive_data_risk")
    @classmethod
    def _enforce_risk_acknowledgement(
        cls, value: bool, info: Any
    ) -> bool:
        policy = info.data.get("git_context_policy", GitContextPolicy.IGNORE)
        if policy == GitContextPolicy.TRACK and not value:
            raise ValueError(
                "acknowledge_sensitive_data_risk must be true when git_context_policy='track'"
            )
        return value


class CommitRequest(BaseModel):
    directory: str
    message: str = Field(..., min_length=1, max_length=200)
    commit_type: CommitType = CommitType.FEATURE
    details: list[str] = Field(default_factory=list)
    files_modified: list[str] = Field(default_factory=list)
    tests_passed: bool = True
    notes: str = ""
    tags: list[str] = Field(default_factory=list)
    ota_log: OtaLog | None = None

    @field_validator("message")
    @classmethod
    def _message_not_blank(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("message must not be blank")
        return stripped


class BranchRequest(BaseModel):
    directory: str
    name: str = Field(..., min_length=1, max_length=50, pattern=r"^[a-z0-9-]+$")
    description: str = Field(..., min_length=1, max_length=200)
    from_branch: str = "main"
    copy_context: bool = True
    tags: list[str] = Field(default_factory=list)


class MergeRequest(BaseModel):
    directory: str
    source_branch: str
    target_branch: str = "main"
    summary: str = Field(..., min_length=1, max_length=500)
    keep_branch: bool = False
    update_roadmap: bool = True


class ContextRequest(BaseModel):
    directory: str
    level: ContextLevel = ContextLevel.SUMMARY
    scope: list[str] = Field(default_factory=list)
    since: date | None = None
    tags: list[str] = Field(default_factory=list)
    format: ContextFormat = ContextFormat.MARKDOWN


class StatusRequest(BaseModel):
    directory: str


class BaseToolResponse(BaseModel):
    status: Literal["success", "error"]
    message: str = ""
    error_code: str = ""
    suggestion: str = ""
    details: dict[str, Any] = Field(default_factory=dict)


class InitResponse(BaseToolResponse):
    structure_created: list[str] = Field(default_factory=list)
    config: dict[str, Any] = Field(default_factory=dict)
    git_context_policy: GitContextPolicy | None = None
    gitignore_updated: bool = False
    security_notice: str = ""


class CommitResponse(BaseToolResponse):
    commit_id: str = ""
    branch: str = ""
    timestamp: str = ""
    files_updated: list[str] = Field(default_factory=list)


class BranchResponse(BaseToolResponse):
    branch_name: str = ""
    branch_path: str = ""
    parent_branch: str = ""
    created_files: list[str] = Field(default_factory=list)
    context_copied: bool = False


class MergeResponse(BaseToolResponse):
    merged_from: str = ""
    merged_into: str = ""
    commits_merged: int = 0
    main_updated: bool = False
    branch_archived: bool = False
    source_branch_status: str = ""
    integration_status: str = ""
    timestamp: str = ""


class ContextResponse(BaseToolResponse):
    level: ContextLevel | None = None
    format: ContextFormat | None = None
    generated_at: str = ""
    data: dict[str, Any] = Field(default_factory=dict)
    rendered: str = ""


class StatusResponse(BaseToolResponse):
    project_name: str = ""
    current_branch: str = ""
    last_commit_id: str = ""
    last_commit_message: str = ""
    active_branches: int = 0
    archived_branches: int = 0
    recent_activity: list[dict[str, Any]] = Field(default_factory=list)
