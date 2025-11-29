"""
Core utilities for Reversecore_MCP.

This package contains security, execution, and exception handling utilities
used across all tool modules.
"""

# Import decorators and helpers for public API
# Import dependency injection container
from reversecore_mcp.core.container import (
    ServiceContainer,
    container,
    get_ghidra_service,
    get_r2_pool,
    get_resource_manager,
)
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_formatting import format_error, get_validation_hint
from reversecore_mcp.core.exceptions import (
    ExecutionTimeoutError,
    OutputLimitExceededError,
    ReversecoreError,
    ToolNotFoundError,
    ValidationError,
)
from reversecore_mcp.core.execution import (
    execute_subprocess_async,
    execute_subprocess_streaming,
)
from reversecore_mcp.core.logging_config import get_logger, setup_logging

# Import shared R2 helper functions
from reversecore_mcp.core.r2_helpers import (
    build_r2_cmd,
    calculate_dynamic_timeout,
    escape_mermaid_chars,
    execute_r2_command,
    parse_json_output,
    strip_address_prefixes,
)

# Import performance optimization modules
from reversecore_mcp.core.r2_pool import R2ConnectionPool, r2_pool
from reversecore_mcp.core.resource_manager import ResourceManager, resource_manager
from reversecore_mcp.core.security import validate_file_path

__all__ = [
    "ReversecoreError",
    "ToolNotFoundError",
    "ExecutionTimeoutError",
    "OutputLimitExceededError",
    "ValidationError",
    "execute_subprocess_streaming",
    "execute_subprocess_async",
    "validate_file_path",
    "format_error",
    "get_validation_hint",
    "get_logger",
    "setup_logging",
    "log_execution",
    "R2ConnectionPool",
    "r2_pool",
    "ResourceManager",
    "resource_manager",
    # R2 helper functions
    "strip_address_prefixes",
    "escape_mermaid_chars",
    "build_r2_cmd",
    "execute_r2_command",
    "parse_json_output",
    "calculate_dynamic_timeout",
    # Dependency injection
    "ServiceContainer",
    "container",
    "get_r2_pool",
    "get_resource_manager",
    "get_ghidra_service",
]
