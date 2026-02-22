from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("mcp")

from gcc_mcp import server


@pytest.fixture(autouse=True)
def _reset_rate_limit() -> None:
    server.rate_limiter.configure(0)


def _init_project(tmp_path: Path) -> None:
    response = server.gcc_init(
        directory=str(tmp_path),
        project_name="MCP Tool Parity",
        project_description="Server tool expansion test",
    )
    assert response["status"] == "success"


def test_server_tool_parity_flow(tmp_path: Path) -> None:
    _init_project(tmp_path)

    branch_response = server.gcc_branch(
        directory=str(tmp_path),
        name="exp-a",
        description="Experiment branch",
    )
    assert branch_response["status"] == "success"

    commit_response = server.gcc_commit(
        directory=str(tmp_path),
        message="Experiment milestone",
        commit_type="feature",
        tags=["perf", "experiment"],
    )
    assert commit_response["status"] == "success"
    assert commit_response["branch"] == "exp-a"

    log_response = server.gcc_log(
        directory=str(tmp_path),
        branch="exp-a",
        commit_type="feature",
        tags=["perf"],
    )
    assert log_response["status"] == "success"
    assert log_response["count"] == 1
    assert log_response["entries"][0]["message"] == "Experiment milestone"

    list_response = server.gcc_list(directory=str(tmp_path))
    assert list_response["status"] == "success"
    assert list_response["count"] == 2
    assert any(item["name"] == "exp-a" and item["current"] for item in list_response["branches"])

    checkout_response = server.gcc_checkout(directory=str(tmp_path), branch="main")
    assert checkout_response["status"] == "success"
    assert checkout_response["current_branch"] == "main"

    delete_response = server.gcc_delete(directory=str(tmp_path), branch="exp-a", archive=True)
    assert delete_response["status"] == "success"
    assert delete_response["mode"] == "archive"

    active_only = server.gcc_list(directory=str(tmp_path), active_only=True)
    assert active_only["status"] == "success"
    assert active_only["count"] == 1
    assert active_only["branches"][0]["name"] == "main"


def test_server_tool_reports_requested_and_resolved_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host_root = tmp_path / "host-worktrees"
    runtime_root = tmp_path / "runtime-repos"
    mapped_repo = runtime_root / "repo-a"
    mapped_repo.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(
        server,
        "engine",
        server.GCCEngine(path_mappings=[(str(host_root), str(runtime_root))]),
    )

    response = server.gcc_init(
        directory=str(host_root / "repo-a"),
        project_name="Mapped MCP Project",
    )

    assert response["status"] == "success"
    assert response["directory_requested"] == str((host_root / "repo-a").resolve())
    assert response["directory_resolved"] == str(mapped_repo.resolve())


def test_server_config_tools(tmp_path: Path) -> None:
    _init_project(tmp_path)

    config_list = server.gcc_config_list(directory=str(tmp_path))
    assert config_list["status"] == "success"
    assert config_list["config"]["project_name"] == "MCP Tool Parity"

    config_get = server.gcc_config_get(directory=str(tmp_path), key="project_name")
    assert config_get["status"] == "success"
    assert config_get["key"] == "project_name"
    assert config_get["value"] == "MCP Tool Parity"

    config_set = server.gcc_config_set(directory=str(tmp_path), key="redaction_mode", value=True)
    assert config_set["status"] == "success"
    assert config_set["config"]["redaction_mode"] is True

    invalid_set = server.gcc_config_set(directory=str(tmp_path), key="unknown_key", value="x")
    assert invalid_set["status"] == "error"
    assert invalid_set["error_code"] == "INVALID_INPUT"


def test_server_log_validation_errors(tmp_path: Path) -> None:
    _init_project(tmp_path)

    invalid_date = server.gcc_log(directory=str(tmp_path), since="2026-13-40")
    assert invalid_date["status"] == "error"
    assert invalid_date["error_code"] == "INVALID_INPUT"

    invalid_type = server.gcc_log(directory=str(tmp_path), commit_type="invalid-type")
    assert invalid_type["status"] == "error"
    assert invalid_type["error_code"] == "INVALID_INPUT"


def test_server_validation_hints_for_common_shape_mismatches(tmp_path: Path) -> None:
    _init_project(tmp_path)

    commit_error = server.gcc_commit(
        directory=str(tmp_path),
        message="Invalid shape payload",
        details="Added parser",  # type: ignore[arg-type]
        files_modified="src/gcc_mcp/server.py",  # type: ignore[arg-type]
        tags="mcp",  # type: ignore[arg-type]
        ota_log="ota text",  # type: ignore[arg-type]
    )
    assert commit_error["status"] == "error"
    commit_hints = commit_error.get("details", {}).get("hints", [])
    assert any("Field 'details' expects list[str], got str." in hint for hint in commit_hints)
    assert any("Field 'files_modified' expects list[str], got str." in hint for hint in commit_hints)
    assert any("Field 'tags' expects list[str], got str." in hint for hint in commit_hints)
    assert any("Field 'ota_log' expects dict[str, str], got str." in hint for hint in commit_hints)

    branch_error = server.gcc_branch(
        directory=str(tmp_path),
        name="hint-test",
        description="Validate hint payload",
        tags="api",  # type: ignore[arg-type]
    )
    assert branch_error["status"] == "error"
    branch_hints = branch_error.get("details", {}).get("hints", [])
    assert any("Field 'tags' expects list[str], got str." in hint for hint in branch_hints)

    context_error = server.gcc_context(
        directory=str(tmp_path),
        scope="main",  # type: ignore[arg-type]
    )
    assert context_error["status"] == "error"
    context_hints = context_error.get("details", {}).get("hints", [])
    assert any("Field 'scope' expects list[str], got str." in hint for hint in context_hints)


def test_server_documented_payload_examples_pass_unchanged(tmp_path: Path) -> None:
    """Keep this test aligned with README 'MCP Payload Shape Examples'."""
    _init_project(tmp_path)

    branch_payload = {
        "directory": str(tmp_path),
        "name": "schema-contracts",
        "description": "Document and validate payload contracts",
        "tags": ["mcp", "api"],
    }
    branch_response = server.gcc_branch(**branch_payload)
    assert branch_response["status"] == "success"

    commit_payload = {
        "directory": str(tmp_path),
        "message": "Checkpoint progress",
        "commit_type": "feature",
        "details": ["Added parser", "Added tests"],
        "files_modified": ["src/gcc_mcp/server.py", "tests/test_server_tools.py"],
        "tags": ["mcp", "docs"],
        "ota_log": {
            "observation": "Validation errors repeated on wrong payload shapes.",
            "thought": "Need explicit list/dict examples and better hints.",
            "action": "Added examples and validation guidance.",
            "result": "Calls succeed with schema-aligned payloads.",
        },
    }
    commit_response = server.gcc_commit(**commit_payload)
    assert commit_response["status"] == "success"

    context_payload = {
        "directory": str(tmp_path),
        "level": "detailed",
        "scope": ["main", "schema-contracts"],
        "tags": ["mcp"],
        "format": "markdown",
    }
    context_response = server.gcc_context(**context_payload)
    assert context_response["status"] == "success"
