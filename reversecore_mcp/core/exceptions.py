"""
Custom exception classes for Reversecore_MCP.

All exceptions inherit from ReversecoreError to allow for centralized
exception handling at the MCP server level.
"""


class ReversecoreError(Exception):
    """Base exception for all Reversecore_MCP errors."""

    pass


class ToolNotFoundError(ReversecoreError):
    """Raised when a required CLI tool is not found in the system."""

    def __init__(self, tool_name: str):
        self.tool_name = tool_name
        super().__init__(f"Tool '{tool_name}' not found. Please install it.")


class ExecutionTimeoutError(ReversecoreError):
    """Raised when a subprocess execution exceeds the timeout limit."""

    def __init__(self, timeout_seconds: int):
        self.timeout_seconds = timeout_seconds
        super().__init__(f"Operation timed out after {timeout_seconds} seconds.")


class OutputLimitExceededError(ReversecoreError):
    """Raised when subprocess output exceeds the maximum allowed size."""

    def __init__(self, max_size: int, actual_size: int):
        self.max_size = max_size
        self.actual_size = actual_size
        super().__init__(
            f"Output limit exceeded: {actual_size} bytes (max: {max_size} bytes). "
            "Output has been truncated."
        )

