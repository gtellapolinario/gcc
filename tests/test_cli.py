from __future__ import annotations

import json
from pathlib import Path

from gcc_mcp.cli import main


def _run_cli_json(args: list[str], capsys) -> dict:
    exit_code = main(args + ["--json"])
    assert exit_code in (0, 1)
    output = capsys.readouterr().out
    return {"exit_code": exit_code, "payload": json.loads(output)}


def test_cli_init_and_status(tmp_path: Path, capsys) -> None:
    init_result = _run_cli_json(
        [
            "init",
            "--directory",
            str(tmp_path),
            "--name",
            "CLI Project",
            "--description",
            "Parity test",
            "--goals",
            "goal-a,goal-b",
        ],
        capsys,
    )
    assert init_result["exit_code"] == 0
    assert init_result["payload"]["status"] == "success"
    assert init_result["payload"]["git_context_policy"] == "ignore"

    status_result = _run_cli_json(["status", "--directory", str(tmp_path)], capsys)
    assert status_result["exit_code"] == 0
    assert status_result["payload"]["status"] == "success"
    assert status_result["payload"]["project_name"] == "CLI Project"


def test_cli_track_policy_requires_ack(tmp_path: Path, capsys) -> None:
    result = _run_cli_json(
        [
            "init",
            "--directory",
            str(tmp_path),
            "--name",
            "CLI Project",
            "--git-context-policy",
            "track",
        ],
        capsys,
    )
    assert result["exit_code"] == 1
    assert result["payload"]["status"] == "error"
    assert result["payload"]["error_code"] == "INVALID_INPUT"
