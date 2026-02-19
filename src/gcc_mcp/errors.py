"""Domain-specific error types for GCC operations."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ErrorCode(str, Enum):
    """Supported error codes exposed by GCC tools."""

    GCC_NOT_FOUND = "GCC_NOT_FOUND"
    BRANCH_EXISTS = "BRANCH_EXISTS"
    BRANCH_NOT_FOUND = "BRANCH_NOT_FOUND"
    INVALID_BRANCH_NAME = "INVALID_BRANCH_NAME"
    MERGE_CONFLICT = "MERGE_CONFLICT"
    INVALID_DIRECTORY = "INVALID_DIRECTORY"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    INVALID_INPUT = "INVALID_INPUT"
    RATE_LIMITED = "RATE_LIMITED"
    GCC_ALREADY_INITIALIZED = "GCC_ALREADY_INITIALIZED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


@dataclass
class GCCError(Exception):
    """Structured exception carrying a stable error contract."""

    code: ErrorCode
    message: str
    suggestion: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_payload(self) -> dict[str, Any]:
        return {
            "status": "error",
            "error_code": self.code.value,
            "message": self.message,
            "suggestion": self.suggestion or "",
            "details": self.details,
        }
