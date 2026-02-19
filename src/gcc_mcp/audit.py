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
    _previous_event_sha256: str | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        """Initialize signer chain state from existing log tail when possible."""
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
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    if not lines:
        return None
    try:
        payload = json.loads(lines[-1])
    except json.JSONDecodeError:
        return None
    event_hash = payload.get("event_sha256")
    if isinstance(event_hash, str) and event_hash:
        return event_hash
    return None
