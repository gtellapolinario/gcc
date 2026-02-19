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
