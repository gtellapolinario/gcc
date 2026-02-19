from __future__ import annotations

import hashlib
import hmac
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


def test_audit_logger_preserves_uuid_and_git_sha(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=log_path, redact_sensitive=True)
    uuid_value = "123e4567-e89b-12d3-a456-426614174000"
    sha_value = "a3f5d2c9b7e1a4f8d6c3b2a1098e7d6c5b4a3f2d"

    logger.log_tool_event(
        tool_name="gcc_status",
        status="success",
        request_payload={"message": f"uuid={uuid_value} sha={sha_value}"},
        response_payload={"status": "success"},
    )

    event = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert uuid_value in event["request"]["message"]
    assert sha_value in event["request"]["message"]


def test_audit_logger_redacts_jwt_and_prefixed_api_key(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=log_path, redact_sensitive=True)

    logger.log_tool_event(
        tool_name="gcc_context",
        status="success",
        request_payload={
            "message": (
                "jwt=eyJhbGciOiJIUzI1NiJ9."
                "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
                "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c "
                "api=ghp_abcdefghijklmnopqrstuvwxyz1234567890"
            )
        },
        response_payload={"status": "success"},
    )

    event = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert event["request"]["message"].count("[REDACTED]") >= 2


def test_audit_logger_truncates_large_fields(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=log_path, redact_sensitive=False, max_field_chars=32)

    logger.log_tool_event(
        tool_name="gcc_context",
        status="success",
        request_payload={"message": "x" * 120},
        response_payload={"status": "success", "details": {"note": "y" * 120}},
    )

    event = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert event["request"]["message"].endswith("...[TRUNCATED]")
    assert len(event["request"]["message"]) == 32
    assert event["response"]["details"]["note"].endswith("...[TRUNCATED]")


def test_audit_logger_truncation_can_be_disabled(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=log_path, redact_sensitive=False, max_field_chars=0)
    message = "z" * 96

    logger.log_tool_event(
        tool_name="gcc_status",
        status="success",
        request_payload={"message": message},
        response_payload={"status": "success"},
    )

    event = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert event["request"]["message"] == message


def test_audit_logger_signed_events_include_hash_chain(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    signing_key = "unit-test-signing-key"
    logger = AuditLogger(
        log_path=log_path,
        redact_sensitive=False,
        signing_key=signing_key,
    )

    logger.log_tool_event(
        tool_name="gcc_status",
        status="success",
        request_payload={"directory": str(tmp_path)},
        response_payload={"status": "success"},
    )
    logger.log_tool_event(
        tool_name="gcc_context",
        status="success",
        request_payload={"level": "summary"},
        response_payload={"status": "success"},
    )

    lines = log_path.read_text(encoding="utf-8").splitlines()
    first_event = json.loads(lines[0])
    second_event = json.loads(lines[1])

    assert first_event["prev_event_sha256"] is None
    assert second_event["prev_event_sha256"] == first_event["event_sha256"]

    for event in (first_event, second_event):
        canonical_payload = dict(event)
        expected_event_sha = canonical_payload.pop("event_sha256")
        expected_signature = canonical_payload.pop("event_signature_hmac_sha256")
        canonical = json.dumps(canonical_payload, ensure_ascii=True, sort_keys=True).encode("utf-8")

        assert hashlib.sha256(canonical).hexdigest() == expected_event_sha
        assert (
            hmac.new(signing_key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
            == expected_signature
        )


def test_audit_logger_recovers_previous_hash_from_existing_log(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    previous_hash = "a" * 64
    log_path.write_text(
        json.dumps(
            {
                "timestamp": "2026-01-01T00:00:00+00:00",
                "event_type": "mcp_tool_call",
                "tool_name": "gcc_status",
                "status": "success",
                "request": {},
                "response": {},
                "prev_event_sha256": None,
                "event_sha256": previous_hash,
                "event_signature_hmac_sha256": "b" * 64,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    logger = AuditLogger(
        log_path=log_path,
        redact_sensitive=False,
        signing_key="unit-test-signing-key",
    )

    logger.log_tool_event(
        tool_name="gcc_context",
        status="success",
        request_payload={"level": "summary"},
        response_payload={"status": "success"},
    )

    last_event = json.loads(log_path.read_text(encoding="utf-8").splitlines()[-1])
    assert last_event["prev_event_sha256"] == previous_hash
