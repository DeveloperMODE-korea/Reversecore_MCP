"""Pydantic models for structured tool results."""

from __future__ import annotations

from typing import Any, Dict, Literal, Optional, Union

from pydantic import BaseModel


class ToolSuccess(BaseModel):
    """Represents a successful tool invocation."""

    status: Literal["success"] = "success"
    data: Union[str, Dict[str, Any]]
    metadata: Optional[Dict[str, Any]] = None


class ToolError(BaseModel):
    """Represents a failed tool invocation."""

    status: Literal["error"] = "error"
    error_code: str
    message: str
    hint: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


ToolResult = Union[ToolSuccess, ToolError]


def success(data: Union[str, Dict[str, Any]], **metadata: Any) -> ToolSuccess:
    """Create a ToolSuccess instance with optional metadata."""
    return ToolSuccess(data=data, metadata=metadata or None)


def failure(
    error_code: str,
    message: str,
    hint: Optional[str] = None,
    **details: Any,
) -> ToolError:
    """Create a ToolError instance with optional hint/details."""
    return ToolError(
        error_code=error_code,
        message=message,
        hint=hint,
        details=details or None,
    )
