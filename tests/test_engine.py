from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from gcc_mcp.engine import GCCEngine
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
