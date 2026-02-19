"""Structured audit logging helpers for MCP operations."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SENSITIVE_KEY_PATTERN = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|authorization)")


@dataclass(slots=True)
class AuditLogger:
    """Append redacted JSONL audit events to disk."""

    log_path: Path | None = None
    redact_sensitive: bool = True

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

        serialized = json.dumps(event, ensure_ascii=True, sort_keys=True)
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(serialized)
                handle.write("\n")
        except OSError:
            # Audit logging must never break tool execution flow.
            return

    def _normalize_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.redact_sensitive:
            return payload
        return _redact_payload(payload)


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
    redacted = re.sub(
        r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization)\s*[:=]\s*([^\s,;]+)",
        r"\1=[REDACTED]",
        redacted,
    )
    redacted = re.sub(r"(?i)\bbearer\s+[a-z0-9\-\._~\+\/]+=*", "Bearer [REDACTED]", redacted)
    redacted = re.sub(r"\b[A-Za-z0-9_\-]{24,}\b", "[REDACTED]", redacted)
    return redacted
