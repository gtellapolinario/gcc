from __future__ import annotations

import json
from pathlib import Path

from gcc_mcp.audit import AuditLogger


def test_audit_logger_disabled_writes_nothing(tmp_path: Path) -> None:
    logger = AuditLogger(log_path=None)
    logger.log_tool_event(
        tool_name="gcc_status",
        status="success",
        request_payload={"directory": str(tmp_path)},
        response_payload={"status": "success", "message": "ok"},
    )
    assert not list(tmp_path.iterdir())


def test_audit_logger_writes_redacted_jsonl(tmp_path: Path) -> None:
    log_path = tmp_path / "logs" / "audit.jsonl"
    logger = AuditLogger(log_path=log_path, redact_sensitive=True)

    logger.log_tool_event(
        tool_name="gcc_commit",
        status="success",
        request_payload={
            "directory": str(tmp_path),
            "message": "token=abcd1234abcd1234abcd1234",
            "authorization": "Bearer super-secret-token",
            "nested": {"password": "super-secret"},
        },
        response_payload={"status": "success", "message": "saved"},
    )

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["tool_name"] == "gcc_commit"
    assert event["status"] == "success"
    assert event["request"]["authorization"] == "[REDACTED]"
    assert event["request"]["nested"]["password"] == "[REDACTED]"
    assert "[REDACTED]" in event["request"]["message"]


def test_audit_logger_without_redaction_keeps_message(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=log_path, redact_sensitive=False)

    logger.log_tool_event(
        tool_name="gcc_context",
        status="success",
        request_payload={"message": "token=plain-text-for-test"},
        response_payload={"status": "success"},
    )

    event = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert event["request"]["message"] == "token=plain-text-for-test"
