"""Structured audit logging helpers for MCP operations."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import ErrorCode, GCCError

SENSITIVE_KEY_PATTERN = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|authorization)")
SENSITIVE_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization)\s*[:=]\s*([^\s,;]+)"
)
BEARER_TOKEN_PATTERN = re.compile(r"(?i)\bbearer\s+[a-z0-9\-\._~\+\/]+=*")
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")
API_KEY_PREFIX_PATTERN = re.compile(
    r"(?i)\b(?:sk|rk|pk|ghp|github_pat)_[A-Za-z0-9_\-]{16,}\b"
)
BASE64_LIKE_PATTERN = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
GENERIC_LONG_TOKEN_PATTERN = re.compile(r"\b[A-Za-z0-9_\-]{64,}\b")
UUID_PATTERN = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}"
    r"-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
)
SHA1_PATTERN = re.compile(r"\b[0-9a-fA-F]{40}\b")


@dataclass(slots=True)
class AuditLogger:
    """Append redacted JSONL audit events to disk."""

    log_path: Path | None = None
    redact_sensitive: bool = True
    max_field_chars: int = 4000
    signing_key: str = ""
    signing_key_id: str = ""
    _previous_event_sha256: str | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        """Initialize signer chain state from existing log tail when possible."""
        self.signing_key = self.signing_key.strip()
        self.signing_key_id = self.signing_key_id.strip()
        if not self.log_path or not self.signing_key:
            return
        self._previous_event_sha256 = _read_last_event_hash(self.log_path)

    @property
    def enabled(self) -> bool:
        """Return whether audit logging is active."""
        return self.log_path is not None

    def log_tool_event(
        self,
        tool_name: str,
        status: str,
        request_payload: dict[str, Any],
        response_payload: dict[str, Any],
    ) -> None:
        """Write one MCP tool audit event."""
        if not self.log_path:
            return

        request_data = self._normalize_payload(request_payload)
        response_data = self._normalize_payload(response_payload)
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "mcp_tool_call",
            "tool_name": tool_name,
            "status": status,
            "request": request_data,
            "response": response_data,
        }
        event_sha256: str | None = None
        if self.signing_key:
            event, event_sha256 = self._sign_event(event)

        serialized = json.dumps(event, ensure_ascii=True, sort_keys=True)
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(serialized)
                handle.write("\n")
            if event_sha256:
                self._previous_event_sha256 = event_sha256
        except OSError:
            # Audit logging must never break tool execution flow.
            return

    def _normalize_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        normalized = payload
        if self.redact_sensitive:
            normalized = _redact_payload(normalized)
        if self.max_field_chars > 0:
            normalized = _truncate_payload(normalized, self.max_field_chars)
        return normalized

    def _sign_event(self, event: dict[str, Any]) -> tuple[dict[str, Any], str]:
        signing_payload = dict(event)
        signing_payload["prev_event_sha256"] = self._previous_event_sha256
        if self.signing_key_id:
            signing_payload["event_signing_key_id"] = self.signing_key_id
        canonical = json.dumps(signing_payload, ensure_ascii=True, sort_keys=True)
        canonical_bytes = canonical.encode("utf-8")
        event_sha256 = hashlib.sha256(canonical_bytes).hexdigest()
        signature = hmac.new(
            self.signing_key.encode("utf-8"),
            canonical_bytes,
            hashlib.sha256,
        ).hexdigest()
        signed_event = dict(signing_payload)
        signed_event["event_sha256"] = event_sha256
        signed_event["event_signature_hmac_sha256"] = signature
        return signed_event, event_sha256


def _redact_payload(payload: Any) -> Any:
    if isinstance(payload, dict):
        redacted: dict[str, Any] = {}
        for key, value in payload.items():
            if SENSITIVE_KEY_PATTERN.search(str(key)):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = _redact_payload(value)
        return redacted
    if isinstance(payload, list):
        return [_redact_payload(item) for item in payload]
    if isinstance(payload, str):
        return _redact_string(payload)
    return payload


def _redact_string(value: str) -> str:
    redacted = value
    redacted = SENSITIVE_ASSIGNMENT_PATTERN.sub(r"\1=[REDACTED]", redacted)
    redacted = BEARER_TOKEN_PATTERN.sub("Bearer [REDACTED]", redacted)
    redacted = JWT_PATTERN.sub("[REDACTED]", redacted)
    redacted = API_KEY_PREFIX_PATTERN.sub("[REDACTED]", redacted)
    redacted = BASE64_LIKE_PATTERN.sub(_redact_high_entropy_match, redacted)
    redacted = GENERIC_LONG_TOKEN_PATTERN.sub(_redact_high_entropy_match, redacted)
    return redacted


def _redact_high_entropy_match(match: re.Match[str]) -> str:
    token = match.group(0)
    if _is_common_identifier(token):
        return token
    return "[REDACTED]"


def _is_common_identifier(token: str) -> bool:
    return bool(UUID_PATTERN.fullmatch(token) or SHA1_PATTERN.fullmatch(token))


def _truncate_payload(payload: Any, max_chars: int) -> Any:
    if isinstance(payload, dict):
        return {key: _truncate_payload(value, max_chars) for key, value in payload.items()}
    if isinstance(payload, list):
        return [_truncate_payload(item, max_chars) for item in payload]
    if isinstance(payload, str):
        return _truncate_string(payload, max_chars)
    return payload


def _truncate_string(value: str, max_chars: int) -> str:
    if len(value) <= max_chars:
        return value
    suffix = "...[TRUNCATED]"
    if max_chars <= len(suffix):
        return suffix[:max_chars]
    return value[: max_chars - len(suffix)] + suffix


def _read_last_event_hash(path: Path) -> str | None:
    chunk_size = 16 * 1024
    try:
        with path.open("rb") as handle:
            handle.seek(0, 2)
            position = handle.tell()
            if position == 0:
                return None

            tail = b""
            while position > 0:
                read_size = min(chunk_size, position)
                position -= read_size
                handle.seek(position)
                tail = handle.read(read_size) + tail

                stripped_tail = tail.rstrip(b"\r\n")
                if b"\n" in stripped_tail or position == 0:
                    break
    except OSError:
        return None

    stripped_tail = tail.rstrip(b"\r\n")
    if not stripped_tail:
        return None

    last_newline_index = stripped_tail.rfind(b"\n")
    if last_newline_index >= 0:
        last_line = stripped_tail[last_newline_index + 1 :]
    else:
        last_line = stripped_tail

    try:
        payload = json.loads(last_line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None

    event_hash = payload.get("event_sha256")
    if isinstance(event_hash, str) and event_hash:
        return event_hash
    return None


def verify_signed_audit_log(
    log_path: Path,
    signing_key: str = "",
    signing_keyring: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Verify HMAC signatures and hash-chain continuity for a signed audit log."""
    normalized_signing_key = signing_key.strip()
    normalized_signing_keyring = _normalize_signing_keyring(signing_keyring or {})

    if not normalized_signing_key and not normalized_signing_keyring:
        raise GCCError(
            ErrorCode.INVALID_INPUT,
            "Signing key material is required for verification.",
            "Provide --signing-key, --signing-key-file, or --signing-keyring-file.",
        )

    try:
        handle = log_path.open("r", encoding="utf-8")
    except OSError as exc:
        raise GCCError(
            ErrorCode.INVALID_INPUT,
            f"Unable to read audit log file: {log_path}",
            "Ensure --log-file points to an existing readable JSONL file.",
        ) from exc

    checked_entries = 0
    previous_event_hash: str | None = None
    with handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue

            checked_entries += 1
            payload = _parse_json_line(line=line, line_number=line_number)
            (
                event_hash,
                signature,
                previous_hash_value,
                event_signing_key_id,
            ) = _extract_signed_event_fields(
                payload=payload,
                line_number=line_number,
            )

            if previous_hash_value != previous_event_hash:
                raise GCCError(
                    ErrorCode.INVALID_INPUT,
                    "Audit chain verification failed.",
                    "Check for tampering, truncation, or out-of-order log lines.",
                    details={
                        "line_number": line_number,
                        "expected_prev_event_sha256": previous_event_hash,
                        "actual_prev_event_sha256": previous_hash_value,
                    },
                )

            canonical_payload = dict(payload)
            canonical_payload.pop("event_sha256", None)
            canonical_payload.pop("event_signature_hmac_sha256", None)
            canonical_bytes = json.dumps(
                canonical_payload,
                ensure_ascii=True,
                sort_keys=True,
            ).encode("utf-8")

            calculated_event_hash = hashlib.sha256(canonical_bytes).hexdigest()
            if not hmac.compare_digest(event_hash, calculated_event_hash):
                raise GCCError(
                    ErrorCode.INVALID_INPUT,
                    "Audit event hash mismatch detected.",
                    "Check for tampering or partial writes in the audit log.",
                    details={
                        "line_number": line_number,
                        "expected_event_sha256": event_hash,
                        "calculated_event_sha256": calculated_event_hash,
                    },
                )

            calculated_signature = hmac.new(
                _resolve_verification_key_for_event(
                    signing_key=normalized_signing_key,
                    signing_keyring=normalized_signing_keyring,
                    event_signing_key_id=event_signing_key_id,
                    line_number=line_number,
                ).encode("utf-8"),
                canonical_bytes,
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(signature, calculated_signature):
                raise GCCError(
                    ErrorCode.INVALID_INPUT,
                    "Audit event signature verification failed.",
                    "Use the correct signing key and verify log integrity.",
                    details={"line_number": line_number},
                )

            previous_event_hash = event_hash

    return {
        "status": "success",
        "message": "Signed audit log verification passed.",
        "entries_checked": checked_entries,
        "log_file": str(log_path),
    }


def _parse_json_line(line: str, line_number: int) -> dict[str, Any]:
    try:
        payload = json.loads(line)
    except json.JSONDecodeError as exc:
        raise GCCError(
            ErrorCode.INVALID_INPUT,
            "Audit log contains malformed JSON.",
            "Fix or remove malformed lines before verification.",
            details={"line_number": line_number},
        ) from exc

    if isinstance(payload, dict):
        return payload

    raise GCCError(
        ErrorCode.INVALID_INPUT,
        "Audit log line must be a JSON object.",
        "Ensure each audit log line is a JSON object.",
        details={"line_number": line_number},
    )


def _extract_signed_event_fields(
    payload: dict[str, Any],
    line_number: int,
) -> tuple[str, str, str | None, str | None]:
    event_hash = payload.get("event_sha256")
    if not isinstance(event_hash, str) or not event_hash:
        raise GCCError(
            ErrorCode.INVALID_INPUT,
            "Missing event_sha256 in signed audit line.",
            "Verify the log was generated with audit signing enabled.",
            details={"line_number": line_number},
        )

    signature = payload.get("event_signature_hmac_sha256")
    if not isinstance(signature, str) or not signature:
        raise GCCError(
            ErrorCode.INVALID_INPUT,
            "Missing event signature in signed audit line.",
            "Verify the log was generated with audit signing enabled.",
            details={"line_number": line_number},
        )

    previous_hash_value = payload.get("prev_event_sha256")
    if previous_hash_value is not None and (
        not isinstance(previous_hash_value, str) or not previous_hash_value
    ):
        raise GCCError(
            ErrorCode.INVALID_INPUT,
            "Invalid prev_event_sha256 value in signed audit line.",
            "Ensure prev_event_sha256 is either null or a non-empty string.",
            details={"line_number": line_number},
        )

    event_signing_key_id = payload.get("event_signing_key_id")
    if event_signing_key_id is not None and (
        not isinstance(event_signing_key_id, str) or not event_signing_key_id
    ):
        raise GCCError(
            ErrorCode.INVALID_INPUT,
            "Invalid event_signing_key_id value in signed audit line.",
            "Ensure event_signing_key_id is omitted or a non-empty string.",
            details={"line_number": line_number},
        )

    return event_hash, signature, previous_hash_value, event_signing_key_id


def _normalize_signing_keyring(signing_keyring: dict[str, str]) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key_id, key_value in signing_keyring.items():
        if not isinstance(key_id, str) or not key_id.strip():
            raise GCCError(
                ErrorCode.INVALID_INPUT,
                "Invalid signing keyring entry.",
                "Each keyring entry must contain a non-empty string key id.",
            )
        if not isinstance(key_value, str) or not key_value.strip():
            raise GCCError(
                ErrorCode.INVALID_INPUT,
                "Invalid signing keyring entry.",
                "Each keyring entry must contain a non-empty string key value.",
            )
        normalized_key_id = key_id.strip()
        normalized_key_value = key_value.strip()
        if normalized_key_id in normalized:
            raise GCCError(
                ErrorCode.INVALID_INPUT,
                "Duplicate signing keyring key id.",
                "Use unique key ids after trimming whitespace.",
            )
        normalized[normalized_key_id] = normalized_key_value
    return normalized


def _resolve_verification_key_for_event(
    signing_key: str,
    signing_keyring: dict[str, str],
    event_signing_key_id: str | None,
    line_number: int,
) -> str:
    if event_signing_key_id:
        if signing_keyring:
            selected_key = signing_keyring.get(event_signing_key_id)
            if not selected_key:
                raise GCCError(
                    ErrorCode.INVALID_INPUT,
                    "Missing signing key for event_signing_key_id.",
                    "Ensure signing keyring contains all key ids used in the log.",
                    details={"line_number": line_number, "event_signing_key_id": event_signing_key_id},
                )
            return selected_key
        if signing_key:
            return signing_key
        raise GCCError(
            ErrorCode.INVALID_INPUT,
            "Missing signing key material for key-id signed event.",
            "Provide signing-keyring-file or signing-key.",
            details={"line_number": line_number, "event_signing_key_id": event_signing_key_id},
        )

    if signing_key:
        return signing_key
    if len(signing_keyring) == 1:
        return next(iter(signing_keyring.values()))

    raise GCCError(
        ErrorCode.INVALID_INPUT,
        "Cannot resolve verification key for event without key id.",
        "Provide --signing-key for legacy logs without event_signing_key_id.",
        details={"line_number": line_number},
    )
