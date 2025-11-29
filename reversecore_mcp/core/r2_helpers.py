"""
Shared helper functions for Radare2 operations.

This module provides common utilities used across multiple tool modules
to avoid circular dependencies between tools.

Functions:
    - _strip_address_prefixes: Remove common address prefixes
    - _escape_mermaid_chars: Escape special characters for Mermaid diagrams
    - _get_r2_project_name: Generate unique project names
    - _calculate_dynamic_timeout: Calculate timeout based on file size
    - _build_r2_cmd: Build radare2 command list
    - _execute_r2_command: Execute radare2 commands asynchronously
    - _extract_first_json: Extract JSON from noisy output
    - _parse_json_output: Parse JSON from command output
"""

import hashlib
import os
import re
from functools import lru_cache
from pathlib import Path

from reversecore_mcp.core import json_utils as json
from reversecore_mcp.core.execution import execute_subprocess_async

# OPTIMIZATION: Pre-compile patterns for better performance
_ADDRESS_PREFIX_PATTERN = re.compile(r"(0x|sym\.|fcn\.)")
_MERMAID_ESCAPE_CHARS = str.maketrans({'"': "'", "(": "[", ")": "]"})
_R2_ANALYSIS_PATTERN = re.compile(r"\b(aaa|aa)\b")


def strip_address_prefixes(address: str) -> str:
    """
    Efficiently strip common address prefixes using regex.

    This is faster than chained .replace() calls for multiple patterns.

    Args:
        address: Address string with potential prefixes

    Returns:
        Address string with prefixes removed
    """
    return _ADDRESS_PREFIX_PATTERN.sub("", address)


def escape_mermaid_chars(text: str) -> str:
    """
    Efficiently escape Mermaid special characters using str.translate().

    This is faster than chained .replace() calls for multiple characters.

    Args:
        text: Text to escape

    Returns:
        Escaped text safe for Mermaid diagrams
    """
    return text.translate(_MERMAID_ESCAPE_CHARS)


@lru_cache(maxsize=128)
def get_r2_project_name(file_path: str) -> str:
    """
    Generate a unique project name based on file path hash.

    Cached to avoid repeated MD5 computation for the same file path.

    Args:
        file_path: Path to the binary file

    Returns:
        MD5 hash of the absolute file path
    """
    abs_path = str(Path(file_path).resolve())
    return hashlib.md5(abs_path.encode()).hexdigest()


@lru_cache(maxsize=128)
def calculate_dynamic_timeout(file_path: str, base_timeout: int = 300) -> int:
    """
    Calculate timeout based on file size.

    Strategy: Base timeout + 2 seconds per MB of file size.
    Cached to avoid repeated file stat calls for the same file.

    Args:
        file_path: Path to the binary file
        base_timeout: Base timeout in seconds

    Returns:
        Calculated timeout in seconds
    """
    try:
        size_mb = os.path.getsize(file_path) / (1024 * 1024)
        # Cap the dynamic addition to avoid extremely long timeouts (max +10 mins)
        additional_time = min(size_mb * 2, 600)
        return int(base_timeout + additional_time)
    except Exception:
        return base_timeout


def build_r2_cmd(file_path: str, r2_commands: list[str], analysis_level: str = "aaa") -> list[str]:
    """
    Build radare2 command.

    Simplified version: Always run analysis if requested, skipping project persistence
    to avoid permission issues and 'exit 1' errors in Docker environments.

    Args:
        file_path: Path to the binary file
        r2_commands: List of radare2 commands to execute
        analysis_level: Analysis level ("aaa", "aa", "-n")

    Returns:
        Complete command list for subprocess execution
    """
    base_cmd = ["r2", "-q"]

    # If we just want to run commands without analysis (adaptive analysis)
    if analysis_level == "-n":
        return base_cmd + ["-n"] + ["-c", ";".join(r2_commands), str(file_path)]

    # Always run analysis + commands
    # We use 'e scr.color=0' to ensure no color codes in output
    combined_cmds = ["e scr.color=0", analysis_level] + r2_commands
    return base_cmd + ["-c", ";".join(combined_cmds), str(file_path)]


async def execute_r2_command(
    file_path: Path,
    r2_commands: list[str],
    analysis_level: str = "aaa",
    max_output_size: int = 10_000_000,
    base_timeout: int = 300,
) -> tuple[str, int]:
    """
    Execute radare2 commands with common pattern.

    This helper consolidates the repeated pattern of:
    1. Calculate dynamic timeout
    2. Build r2 command
    3. Execute subprocess

    Args:
        file_path: Path to the binary file (already validated)
        r2_commands: List of radare2 commands to execute
        analysis_level: Analysis level ("aaa", "aa", "-n")
        max_output_size: Maximum output size in bytes
        base_timeout: Base timeout in seconds

    Returns:
        Tuple of (output, bytes_read)
    """
    effective_timeout = calculate_dynamic_timeout(str(file_path), base_timeout)
    cmd = build_r2_cmd(str(file_path), r2_commands, analysis_level)

    output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=max_output_size,
        timeout=effective_timeout,
    )

    return output, bytes_read


def extract_first_json(text: str) -> str | None:
    """
    Extract the first valid JSON object or array from a string.

    Handles nested structures and ignores surrounding garbage.
    Optimized to O(n) by minimizing redundant scanning.

    Args:
        text: Input text potentially containing JSON

    Returns:
        The extracted JSON string, or None if no valid JSON found
    """
    text = text.strip()
    if not text:
        return None

    # Quick optimization: Try parsing the whole string first
    if text[0] in ("{", "["):
        try:
            json.loads(text)
            return text
        except json.JSONDecodeError:
            pass

    # Need to extract JSON from noisy output
    i = 0
    text_len = len(text)

    while i < text_len:
        char = text[i]

        # Skip non-JSON start characters
        if char not in ("{", "["):
            i += 1
            continue

        # Found potential JSON start - check for false positives
        if i + 1 < text_len and text[i + 1] in (" ", "\t"):
            next_idx = i + 2
            while next_idx < text_len and text[next_idx] in (" ", "\t", "\n", "\r"):
                next_idx += 1
            if next_idx < text_len and text[next_idx] == char:
                i += 1
                continue

        # Try to extract JSON starting from this position
        stack = []
        start_idx = i
        in_string = False
        escape_next = False
        j = i

        while j < text_len:
            c = text[j]

            if escape_next:
                escape_next = False
                j += 1
                continue

            if c == "\\" and in_string:
                escape_next = True
                j += 1
                continue

            if c == '"':
                in_string = not in_string
                j += 1
                continue

            if not in_string:
                if c in ("{", "["):
                    stack.append(c)
                elif c in ("}", "]"):
                    if not stack:
                        break

                    last = stack[-1]
                    if (c == "}" and last == "{") or (c == "]" and last == "["):
                        stack.pop()
                        if not stack:
                            candidate = text[start_idx : j + 1]
                            try:
                                json.loads(candidate)
                                return candidate
                            except json.JSONDecodeError:
                                i = j + 1
                                break
                    else:
                        break

            j += 1

        if i == start_idx:
            i += 1

    return None


def parse_json_output(output: str):
    """
    Safely parse JSON from command output.

    Tries to extract JSON from output that may contain non-JSON text
    (like warnings, debug messages, etc.) and parse it.

    Args:
        output: Raw command output that may contain JSON

    Returns:
        Parsed JSON object (dict/list) or None if parsing fails

    Raises:
        json.JSONDecodeError: If JSON is found but invalid
    """
    json_str = extract_first_json(output)

    if json_str is not None:
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            pass

    return json.loads(output)


def remove_analysis_commands(command: str) -> str:
    """
    Remove explicit radare2 analysis commands (aaa, aa) from a command string.

    Args:
        command: Radare2 command string

    Returns:
        Command string with analysis commands removed
    """
    return _R2_ANALYSIS_PATTERN.sub("", command).strip(" ;")


# Legacy aliases for backward compatibility (deprecated)
# These will be removed in a future version
_strip_address_prefixes = strip_address_prefixes
_escape_mermaid_chars = escape_mermaid_chars
_get_r2_project_name = get_r2_project_name
_calculate_dynamic_timeout = calculate_dynamic_timeout
_build_r2_cmd = build_r2_cmd
_execute_r2_command = execute_r2_command
_extract_first_json = extract_first_json
_parse_json_output = parse_json_output
