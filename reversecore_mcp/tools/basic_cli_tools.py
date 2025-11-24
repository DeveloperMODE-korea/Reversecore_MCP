"""Basic CLI tool wrappers for common utilities like file, strings, binwalk, and radare2."""

from fastmcp import Context
from pathlib import Path

from reversecore_mcp.core.command_spec import validate_r2_command
from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.execution import execute_subprocess_async
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.resilience import circuit_breaker
from reversecore_mcp.core.result import ToolResult, success
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.core.validators import validate_tool_parameters

from .r2_helpers import (
    _execute_r2_command,
    get_r2_analysis_pattern,
)

# Load default timeout from configuration
DEFAULT_TIMEOUT = get_config().default_tool_timeout

logger = get_logger(__name__)


async def run_file(file_path: str, timeout: int = DEFAULT_TIMEOUT) -> ToolResult:
    """Identify file metadata using the ``file`` CLI utility."""

    validated_path = validate_file_path(file_path)
    cmd = ["file", str(validated_path)]
    output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=1_000_000,
        timeout=timeout,
    )
    return success(output.strip(), bytes_read=bytes_read)


@log_execution(tool_name="run_strings")
@track_metrics("run_strings")
@handle_tool_errors
async def run_strings(
    file_path: str,
    min_length: int = 4,
    max_output_size: int = 10_000_000,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """Extract printable strings using the ``strings`` CLI."""

    validate_tool_parameters(
        "run_strings",
        {"min_length": min_length, "max_output_size": max_output_size},
    )
    
    # Enforce a reasonable minimum output size to prevent accidental truncation
    # 1KB is too small for meaningful string analysis
    if max_output_size < 1024 * 1024:  # Enforce 1MB minimum
        max_output_size = 1024 * 1024
        
    validated_path = validate_file_path(file_path)
    cmd = ["strings", "-n", str(min_length), str(validated_path)]
    output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=max_output_size,
        timeout=timeout,
    )
    
    # Truncate output for LLM consumption if too large
    # 50KB is roughly 12-15k tokens, which is a safe limit for most models
    LLM_SAFE_LIMIT = 50 * 1024 
    
    if len(output) > LLM_SAFE_LIMIT:
        truncated_output = output[:LLM_SAFE_LIMIT]
        warning_msg = (
            f"\n\n[WARNING] Output truncated! Total size: {len(output)} bytes. "
            f"Showing first {LLM_SAFE_LIMIT} bytes.\n"
            "To analyze the full content, consider using 'grep' or processing the file directly."
        )
        return success(truncated_output + warning_msg, bytes_read=bytes_read, truncated=True)
        
    return success(output, bytes_read=bytes_read)


@log_execution(tool_name="run_radare2")
@track_metrics("run_radare2")
@circuit_breaker("run_radare2", failure_threshold=5, recovery_timeout=60)
@handle_tool_errors
async def run_radare2(
    file_path: str,
    r2_command: str,
    max_output_size: int = 10_000_000,
    timeout: int = DEFAULT_TIMEOUT,
    ctx: Context = None,
) -> ToolResult:
    """Execute vetted radare2 commands for binary triage."""

    validate_tool_parameters("run_radare2", {"r2_command": r2_command})
    validated_path = validate_file_path(file_path)
    validated_command = validate_r2_command(r2_command)
    
    # Adaptive analysis logic
    # Use 'aa' (basic analysis) instead of 'aaa' (advanced analysis) for better performance
    # 'aaa' is often overkill for automated tasks and causes timeouts on large binaries
    analysis_level = "aa"
    
    # Simple information commands don't need analysis
    simple_commands = ["i", "iI", "iz", "il", "is", "ie", "it"]
    if validated_command in simple_commands or validated_command.startswith("i "):
        analysis_level = "-n"
    
    # If user explicitly requested analysis, handle it via caching
    if "aaa" in validated_command or "aa" in validated_command:
        # Remove explicit analysis commands as they are handled by _build_r2_cmd
        # OPTIMIZATION: Use pre-compiled regex pattern instead of chained replace
        validated_command = get_r2_analysis_pattern().sub('', validated_command).strip(" ;")
    
    # Use helper function to execute radare2 command
    try:
        output, bytes_read = await _execute_r2_command(
            validated_path,
            [validated_command],
            analysis_level=analysis_level,
            max_output_size=max_output_size,
            base_timeout=timeout,
        )
        return success(output, bytes_read=bytes_read)
    except Exception as e:
        # Log error to client if context is available
        if ctx:
            await ctx.error(f"radare2 command '{validated_command}' failed: {str(e)}")
        raise


@log_execution(tool_name="run_binwalk")
@track_metrics("run_binwalk")
@handle_tool_errors
async def run_binwalk(
    file_path: str,
    depth: int = 8,
    max_output_size: int = 10_000_000,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """Analyze binaries for embedded content using binwalk."""

    validated_path = validate_file_path(file_path)
    cmd = ["binwalk", "-A", "-d", str(depth), str(validated_path)]
    output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=max_output_size,
        timeout=timeout,
    )
    return success(output, bytes_read=bytes_read)
