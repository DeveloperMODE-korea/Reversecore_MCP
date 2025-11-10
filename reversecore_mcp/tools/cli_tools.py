"""
CLI tool wrappers for Reversecore_MCP.

This module provides MCP tools that wrap common reverse engineering CLI tools
such as strings, radare2, etc.
"""

import subprocess

from fastmcp import FastMCP

from reversecore_mcp.core.exceptions import (
    ExecutionTimeoutError,
    OutputLimitExceededError,
    ReversecoreError,
    ToolNotFoundError,
)
from reversecore_mcp.core.execution import execute_subprocess_streaming
from reversecore_mcp.core.security import sanitize_command_string, validate_file_path


def register_cli_tools(mcp: FastMCP) -> None:
    """
    Register all CLI tool wrappers with the FastMCP server.

    Args:
        mcp: The FastMCP server instance to register tools with
    """
    mcp.tool(run_strings)
    mcp.tool(run_radare2)


def run_strings(
    file_path: str,
    min_length: int = 4,
    max_output_size: int = 10_000_000,
    timeout: int = 300,
) -> str:
    """
    Extract printable strings from a binary file using the strings command.

    This tool runs the 'strings' command on the specified file and returns
    all printable strings found. Useful for initial triage and finding
    interesting text in binaries.

    Args:
        file_path: Path to the binary file to analyze
        min_length: Minimum string length to extract (default: 4)
        max_output_size: Maximum output size in bytes (default: 10MB)
        timeout: Maximum execution time in seconds (default: 300)

    Returns:
        Extracted strings, one per line. May be truncated if output exceeds
        max_output_size.

    Raises:
        Returns error message string if execution fails (never raises exceptions)
    """
    try:
        # Validate file path
        validated_path = validate_file_path(file_path)

        # Build command: strings -n <min_length> <file_path>
        cmd = ["strings", "-n", str(min_length), validated_path]

        # Execute with streaming
        output, bytes_read = execute_subprocess_streaming(
            cmd, max_output_size=max_output_size, timeout=timeout
        )

        return output

    except ToolNotFoundError as e:
        return f"Error: {e}"
    except ExecutionTimeoutError as e:
        return f"Error: {e}"
    except ValueError as e:
        return f"Error: Invalid file path - {e}"
    except subprocess.CalledProcessError as e:
        stderr = e.stderr if e.stderr else "Unknown error"
        return f"Error: Command failed with exit code {e.returncode}. stderr: {stderr}"
    except Exception as e:
        return f"Error: Unexpected error - {type(e).__name__}: {e}"


def run_radare2(
    file_path: str,
    r2_command: str,
    max_output_size: int = 10_000_000,
    timeout: int = 300,
) -> str:
    """
    Execute a radare2 command on a binary file.

    This tool opens a file in radare2 and executes the specified command.
    Useful for disassembly, analysis, and various radare2 operations.

    Args:
        file_path: Path to the binary file to analyze
        r2_command: Radare2 command to execute (e.g., "pdf @ main", "afl", "iS")
        max_output_size: Maximum output size in bytes (default: 10MB)
        timeout: Maximum execution time in seconds (default: 300)

    Returns:
        Output from the radare2 command. May be truncated if output exceeds
        max_output_size.

    Raises:
        Returns error message string if execution fails (never raises exceptions)
    """
    try:
        # Validate file path
        validated_path = validate_file_path(file_path)

        # Basic validation of r2_command (non-empty)
        sanitized_cmd = sanitize_command_string(r2_command)

        # Build command: r2 -q -c "<command>" <file_path>
        # Note: We pass r2_command as a single argument to -c flag
        # r2 expects: r2 -q -c "pdf @ main" file.exe
        cmd = ["r2", "-q", "-c", sanitized_cmd, validated_path]

        # Execute with streaming
        output, bytes_read = execute_subprocess_streaming(
            cmd, max_output_size=max_output_size, timeout=timeout
        )

        return output

    except ToolNotFoundError as e:
        return f"Error: {e}"
    except ExecutionTimeoutError as e:
        return f"Error: {e}"
    except ValueError as e:
        return f"Error: Invalid input - {e}"
    except subprocess.CalledProcessError as e:
        stderr = e.stderr if e.stderr else "Unknown error"
        return f"Error: Command failed with exit code {e.returncode}. stderr: {stderr}"
    except Exception as e:
        return f"Error: Unexpected error - {type(e).__name__}: {e}"

