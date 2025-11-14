"""
Core utilities for Reversecore_MCP.

This package contains security, execution, and exception handling utilities
used across all tool modules.
"""

# Import deprecated functions for backward compatibility
from reversecore_mcp.core.config import get_settings, reload_settings
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_formatting import format_error, get_validation_hint
from reversecore_mcp.core.exceptions import (
    ExecutionTimeoutError,
    OutputLimitExceededError,
    ReversecoreError,
    ToolNotFoundError,
    ValidationError,
)
from reversecore_mcp.core.execution import execute_subprocess_streaming
from reversecore_mcp.core.logging_config import get_logger, setup_logging
from reversecore_mcp.core.security import sanitize_command_string, validate_file_path

# Export new SettingsManager for recommended usage
from reversecore_mcp.core.settings_manager import SettingsManager

__all__ = [
    "ReversecoreError",
    "ToolNotFoundError",
    "ExecutionTimeoutError",
    "OutputLimitExceededError",
    "ValidationError",
    "execute_subprocess_streaming",
    "validate_file_path",
    "sanitize_command_string",
    "format_error",
    "get_validation_hint",
    "get_logger",
    "setup_logging",
    "get_settings",  # Deprecated, use SettingsManager.get() instead
    "reload_settings",  # Deprecated, use SettingsManager.clear() then .get() instead
    "log_execution",
    "SettingsManager",  # Recommended way to access settings
]

