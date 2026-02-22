from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from gcc_mcp.engine import GCCEngine
from gcc_mcp.errors import GCCError
from gcc_mcp.models import (
    BranchRequest,
    CommitRequest,
    ContextRequest,
    InitRequest,
    MergeRequest,
    StatusRequest,
)


@pytest.fixture()
def engine() -> GCCEngine:
    return GCCEngine()


def test_initialize_creates_expected_structure(tmp_path: Path, engine: GCCEngine) -> None:
    response = engine.initialize(
        InitRequest(
            directory=str(tmp_path),
            project_name="Demo Project",
            project_description="Tracking context for testing.",
            initial_goals=["Implement server", "Write tests"],
        )
    )

    assert response.status == "success"
    assert (tmp_path / ".GCC" / "main.md").exists()
    assert (tmp_path / ".GCC" / ".gcc-config.yaml").exists()
    assert (tmp_path / ".GCC" / "branches" / "main" / "commit.md").exists()
    assert (tmp_path / ".GCC" / "branches" / "main" / "log.md").exists()
    assert (tmp_path / ".GCC" / "branches" / "main" / "metadata.yaml").exists()

    config = yaml.safe_load((tmp_path / ".GCC" / ".gcc-config.yaml").read_text(encoding="utf-8"))
    assert config["project_name"] == "Demo Project"
    assert config["current_branch"] == "main"
    assert config["git_context_policy"] == "ignore"
    assert (tmp_path / ".gitignore").exists()
    assert ".GCC/" in (tmp_path / ".gitignore").read_text(encoding="utf-8")
    assert response.git_context_policy == "ignore"
    assert response.security_notice


def test_initialize_track_policy_requires_acknowledgement(tmp_path: Path, engine: GCCEngine) -> None:
    with pytest.raises(ValidationError):
        InitRequest(
            directory=str(tmp_path),
            project_name="Demo Project",
            git_context_policy="track",
            acknowledge_sensitive_data_risk=False,
        )

    response = engine.initialize(
        InitRequest(
            directory=str(tmp_path),
            project_name="Demo Project",
            git_context_policy="track",
            acknowledge_sensitive_data_risk=True,
        )
    )
    assert response.status == "success"
    assert response.git_context_policy == "track"
    gitignore = tmp_path / ".gitignore"
    if gitignore.exists():
        assert ".GCC/" not in gitignore.read_text(encoding="utf-8")


def test_commit_updates_files_and_metadata(tmp_path: Path, engine: GCCEngine) -> None:
    engine.initialize(
        InitRequest(
            directory=str(tmp_path),
            project_name="Demo Project",
        )
    )

    response = engine.commit(
        CommitRequest(
            directory=str(tmp_path),
            message="Implemented parser",
            details=["Added parsing module", "Added validations"],
            files_modified=["src/parser.py", "tests/test_parser.py"],
            tags=["parser", "feature"],
            tests_passed=True,
            ota_log={
                "observation": "Input format was inconsistent",
                "thought": "Need stricter normalization",
                "action": "Added parser normalization",
                "result": "Stable parsing across inputs",
            },
        )
    )

    assert response.status == "success"
    commit_md = (tmp_path / ".GCC" / "branches" / "main" / "commit.md").read_text(encoding="utf-8")
    assert "Implemented parser" in commit_md
    assert response.commit_id in commit_md

    metadata = yaml.safe_load(
        (tmp_path / ".GCC" / "branches" / "main" / "metadata.yaml").read_text(encoding="utf-8")
    )
    assert metadata["commits"]["count"] == 1
    assert metadata["history"][0]["message"] == "Implemented parser"
    assert metadata["history"][0]["tags"] == ["parser", "feature"]


def test_branch_and_merge_flow(tmp_path: Path, engine: GCCEngine) -> None:
    engine.initialize(
        InitRequest(
            directory=str(tmp_path),
            project_name="Demo Project",
        )
    )

    branch_response = engine.branch(
        BranchRequest(
            directory=str(tmp_path),
            name="try-playwright",
            description="Try Playwright for dynamic pages",
            from_branch="main",
            tags=["experiment"],
        )
    )
    assert branch_response.status == "success"

    engine.commit(
        CommitRequest(
            directory=str(tmp_path),
            message="Playwright prototype works",
            commit_type="feature",
            tags=["experiment", "performance"],
        )
    )

    merge_response = engine.merge(
        MergeRequest(
            directory=str(tmp_path),
            source_branch="try-playwright",
            target_branch="main",
            summary="Playwright handles JS-rendered pages and improves speed",
            keep_branch=False,
            update_roadmap=True,
        )
    )
    assert merge_response.status == "success"
    assert merge_response.merged_from == "try-playwright"
    assert merge_response.merged_into == "main"

    source_metadata = yaml.safe_load(
        (
            tmp_path
            / ".GCC"
            / "branches"
            / "try-playwright"
            / "metadata.yaml"
        ).read_text(encoding="utf-8")
    )
    assert source_metadata["branch"]["status"] == "merged"
    assert source_metadata["branch"]["integration_status"] == "merged"


def test_merge_keep_branch_true_keeps_source_active(tmp_path: Path, engine: GCCEngine) -> None:
    engine.initialize(
        InitRequest(
            directory=str(tmp_path),
            project_name="Demo Project",
        )
    )
    engine.branch(
        BranchRequest(
            directory=str(tmp_path),
            name="experiment-fast-path",
            description="Try fast-path implementation",
        )
    )
    engine.commit(
        CommitRequest(
            directory=str(tmp_path),
            message="Fast-path prototype complete",
            tags=["experiment"],
        )
    )

    response = engine.merge(
        MergeRequest(
            directory=str(tmp_path),
            source_branch="experiment-fast-path",
            target_branch="main",
            summary="Integrated fast-path behavior",
            keep_branch=True,
        )
    )
    assert response.status == "success"
    assert response.source_branch_status == "active"
    assert response.integration_status == "merged"

    metadata = yaml.safe_load(
        (
            tmp_path
            / ".GCC"
            / "branches"
            / "experiment-fast-path"
            / "metadata.yaml"
        ).read_text(encoding="utf-8")
    )
    assert metadata["branch"]["status"] == "active"
    assert metadata["branch"]["integration_status"] == "merged"


def test_context_and_status_outputs(tmp_path: Path, engine: GCCEngine) -> None:
    engine.initialize(
        InitRequest(
            directory=str(tmp_path),
            project_name="Demo Project",
        )
    )
    engine.commit(
        CommitRequest(
            directory=str(tmp_path),
            message="Setup baseline",
            tags=["setup"],
        )
    )
    engine.commit(
        CommitRequest(
            directory=str(tmp_path),
            message="Implemented API endpoint",
            tags=["api"],
        )
    )

    context = engine.get_context(
        ContextRequest(
            directory=str(tmp_path),
            level="detailed",
            tags=["api"],
            format="json",
        )
    )
    assert context.status == "success"
    assert context.data["summary"]["returned_branches"] == 1
    commits = context.data["branches"][0]["commits"]
    assert len(commits) == 1
    assert commits[0]["message"] == "Implemented API endpoint"

    status = engine.get_status(StatusRequest(directory=str(tmp_path)))
    assert status.status == "success"
    assert status.project_name == "Demo Project"
    assert status.current_branch == "main"
    assert status.active_branches == 1


def test_context_redaction_mode(tmp_path: Path, engine: GCCEngine) -> None:
    engine.initialize(
        InitRequest(
            directory=str(tmp_path),
            project_name="Demo Project",
        )
    )
    engine.commit(
        CommitRequest(
            directory=str(tmp_path),
            message="Configured token=abcd1234abcd1234abcd1234",
            notes="password=super-secret-value",
            tags=["security"],
        )
    )

    context = engine.get_context(
        ContextRequest(
            directory=str(tmp_path),
            level="detailed",
            format="json",
            redact_sensitive=True,
        )
    )
    assert context.status == "success"
    assert context.redaction_applied is True
    commits = context.data["branches"][0]["commits"]
    assert "[REDACTED]" in commits[0]["message"] or "[REDACTED_PATH]" in commits[0]["message"]


def test_set_config_current_branch_uses_checkout_side_effects(
    tmp_path: Path, engine: GCCEngine
) -> None:
    engine.initialize(
        InitRequest(
            directory=str(tmp_path),
            project_name="Demo Project",
        )
    )
    engine.branch(
        BranchRequest(
            directory=str(tmp_path),
            name="feature-a",
            description="Feature branch",
            from_branch="main",
        )
    )

    updated = engine.set_config(str(tmp_path), "current_branch", "main")
    assert updated["current_branch"] == "main"
    activity = updated.get("activity_log", [])
    assert activity
    assert activity[-1]["action"] == "CHECKOUT"
    assert activity[-1]["branch"] == "main"


def test_delete_branch_invalid_name_rejected(tmp_path: Path, engine: GCCEngine) -> None:
    engine.initialize(
        InitRequest(
            directory=str(tmp_path),
            project_name="Demo Project",
        )
    )

    with pytest.raises(GCCError) as exc_info:
        engine.delete_branch(
            directory=str(tmp_path),
            branch_name="../..",
            force=True,
        )
    assert "Invalid branch name" in str(exc_info.value)


def test_branch_from_branch_validation_rejects_path_segments(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        BranchRequest(
            directory=str(tmp_path),
            name="feature-safe",
            description="Attempt unsafe parent branch input",
            from_branch="../main",
        )


def test_commit_rejects_tampered_current_branch_value(tmp_path: Path, engine: GCCEngine) -> None:
    engine.initialize(
        InitRequest(
            directory=str(tmp_path),
            project_name="Demo Project",
        )
    )
    config_path = tmp_path / ".GCC" / ".gcc-config.yaml"
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    config["current_branch"] = "../main"
    config_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")

    with pytest.raises(GCCError) as exc_info:
        engine.commit(
            CommitRequest(
                directory=str(tmp_path),
                message="Should fail with invalid branch in config",
            )
        )

    assert exc_info.value.code.value == "INVALID_BRANCH_NAME"


def test_resolve_directory_applies_path_mapping(tmp_path: Path) -> None:
    host_root = tmp_path / "host-worktrees"
    runtime_root = tmp_path / "runtime-repos"
    mapped_repo = runtime_root / "repo-a"
    mapped_repo.mkdir(parents=True, exist_ok=True)

    engine = GCCEngine(path_mappings=[(str(host_root), str(runtime_root))])

    resolved = engine.resolve_directory(str(host_root / "repo-a"))
    assert resolved["directory_requested"] == str((host_root / "repo-a").resolve())
    assert resolved["directory_resolved"] == str(mapped_repo.resolve())


def test_resolve_directory_falls_back_to_existing_mapped_parent(tmp_path: Path) -> None:
    host_worktrees = tmp_path / "host-worktrees"
    runtime_repo_root = tmp_path / "runtime-repos" / "projectmist"
    runtime_repo_root.mkdir(parents=True, exist_ok=True)

    engine = GCCEngine(path_mappings=[(str(host_worktrees), str(runtime_repo_root))])

    resolved = engine.resolve_directory(str(host_worktrees / "five-bears-enter-6pm"))
    assert resolved["directory_requested"] == str((host_worktrees / "five-bears-enter-6pm").resolve())
    assert resolved["directory_resolved"] == str(runtime_repo_root.resolve())


def test_status_uses_parent_fallback_for_missing_mapped_leaf(tmp_path: Path) -> None:
    host_worktrees = tmp_path / "host-worktrees"
    runtime_root = tmp_path / "runtime-repos"
    runtime_repo_root = runtime_root / "projectmist"
    runtime_repo_root.mkdir(parents=True, exist_ok=True)

    engine = GCCEngine(
        path_mappings=[(str(host_worktrees), str(runtime_repo_root))],
        allowed_roots=[str(runtime_root)],
    )
    engine.initialize(
        InitRequest(
            directory=str(runtime_repo_root),
            project_name="Mapped Parent Project",
        )
    )

    status = engine.get_status(StatusRequest(directory=str(host_worktrees / "feature-worktree")))
    assert status.status == "success"
    assert status.project_name == "Mapped Parent Project"


def test_resolve_directory_relative_path_returns_client_cwd_guidance(tmp_path: Path) -> None:
    allowed_root = tmp_path / "allowed-root"
    allowed_root.mkdir(parents=True, exist_ok=True)
    engine = GCCEngine(allowed_roots=[str(allowed_root)])

    with pytest.raises(GCCError) as exc_info:
        engine.resolve_directory(".")

    assert exc_info.value.code.value == "INVALID_DIRECTORY"
    assert exc_info.value.details["failure_reason"] == "relative_path_runtime_cwd"
    assert exc_info.value.details["relative_input"] is True
    assert isinstance(exc_info.value.details["existing_suggestions"], list)
    assert exc_info.value.details["directory_requested"] == "."
    assert exc_info.value.details["directory_resolved"] is None
    assert "requested_directory" in exc_info.value.details
    assert "client cwd" in (exc_info.value.suggestion or "").lower()


def test_resolve_directory_invalid_error_includes_existing_suggestions(tmp_path: Path) -> None:
    host_worktrees = tmp_path / "host-worktrees"
    runtime_repo_root = tmp_path / "runtime-repos" / "projectmist"
    runtime_repo_root.mkdir(parents=True, exist_ok=True)
    allowed_root = tmp_path / "allowed-root"
    allowed_root.mkdir(parents=True, exist_ok=True)

    engine = GCCEngine(
        path_mappings=[(str(host_worktrees), str(runtime_repo_root))],
        allowed_roots=[str(allowed_root)],
    )

    with pytest.raises(GCCError) as exc_info:
        engine.resolve_directory(str(host_worktrees / "missing-worktree"))

    assert exc_info.value.code.value == "INVALID_DIRECTORY"
    assert exc_info.value.details["failure_reason"] == "outside_allowed_roots"
    assert exc_info.value.details["directory_requested"] == str(host_worktrees / "missing-worktree")
    assert exc_info.value.details["directory_resolved"] is None
    assert "requested_directory" in exc_info.value.details
    suggestions = exc_info.value.details["existing_suggestions"]
    assert suggestions
    assert suggestions[0]["path"] == str(runtime_repo_root.resolve())
    confidences = [item["confidence"] for item in suggestions]
    assert confidences == sorted(confidences, reverse=True)


def test_initialize_uses_mapped_runtime_directory(tmp_path: Path) -> None:
    host_root = tmp_path / "host-worktrees"
    runtime_root = tmp_path / "runtime-repos"
    mapped_repo = runtime_root / "repo-b"
    mapped_repo.mkdir(parents=True, exist_ok=True)

    engine = GCCEngine(path_mappings=[(str(host_root), str(runtime_root))])
    response = engine.initialize(
        InitRequest(
            directory=str(host_root / "repo-b"),
            project_name="Mapped Project",
        )
    )

    assert response.status == "success"
    assert (mapped_repo / ".GCC" / "main.md").exists()


def test_resolve_directory_enforces_allowed_roots(tmp_path: Path) -> None:
    allowed_root = tmp_path / "allowed"
    disallowed_root = tmp_path / "outside"
    disallowed_repo = disallowed_root / "repo-x"
    disallowed_repo.mkdir(parents=True, exist_ok=True)

    engine = GCCEngine(allowed_roots=[str(allowed_root)])

    with pytest.raises(GCCError) as exc_info:
        engine.resolve_directory(str(disallowed_repo))

    assert exc_info.value.code.value == "INVALID_DIRECTORY"
    assert "outside configured allowed roots" in exc_info.value.message
