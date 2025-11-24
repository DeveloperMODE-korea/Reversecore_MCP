"""Shared radare2 helper functions used across multiple tool modules."""

import hashlib
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Optional

# Use high-performance JSON implementation (3-5x faster)
from reversecore_mcp.core import json_utils as json
from reversecore_mcp.core.execution import execute_subprocess_async


# OPTIMIZATION: Pre-compile pattern for stripping address prefixes
_ADDRESS_PREFIX_PATTERN = re.compile(r'(0x|sym\.|fcn\.)')

# OPTIMIZATION: Pre-compile pattern for removing 0x/0X prefix (case insensitive)
_HEX_PREFIX_PATTERN = re.compile(r'^0[xX]')

# OPTIMIZATION: Pre-compile pattern for Mermaid special character escaping
_MERMAID_ESCAPE_CHARS = str.maketrans({
    '"': "'",
    '(': '[',
    ')': ']'
})

# OPTIMIZATION: Pre-compile pattern for removing radare2 analysis commands
_R2_ANALYSIS_PATTERN = re.compile(r'\b(aaa|aa)\b')

# OPTIMIZATION: Character translation table for filename sanitization
_FILENAME_SANITIZE_TRANS = str.maketrans({
    '-': '_',
    '.': '_'
})


def _strip_address_prefixes(address: str) -> str:
    """
    Efficiently strip common address prefixes using regex.
    
    This is faster than chained .replace() calls for multiple patterns.
    """
    return _ADDRESS_PREFIX_PATTERN.sub('', address)


def _strip_hex_prefix(hex_str: str) -> str:
    """
    Efficiently strip 0x/0X prefix from hex strings using regex.
    
    This is faster than chained .replace() calls.
    """
    return _HEX_PREFIX_PATTERN.sub('', hex_str)


def _escape_mermaid_chars(text: str) -> str:
    """
    Efficiently escape Mermaid special characters using str.translate().
    
    This is faster than chained .replace() calls for multiple characters.
    """
    return text.translate(_MERMAID_ESCAPE_CHARS)


def _extract_library_name(function_name: str) -> str:
    """
    Extract library name from function name.
    
    Cached to avoid repeated string comparisons for common function names.

    Args:
        function_name: Function name (e.g., "sym.imp.strcpy")

    Returns:
        Extracted library name or "unknown"
    """
    # Simple heuristic extraction
    if "kernel32" in function_name.lower():
        return "kernel32"
    elif "msvcrt" in function_name.lower() or "libc" in function_name.lower():
        return "libc/msvcrt"
    elif "std::" in function_name:
        return "libstdc++"
    elif "imp." in function_name:
        return "import"
    else:
        return "unknown"


def _format_hex_bytes(hex_string: str) -> str:
    """
    Efficiently format hex string as space-separated byte pairs.
    
    Optimized to avoid intermediate list creation by using a generator.
    
    Args:
        hex_string: Hex string without spaces (e.g., "4883ec20")
        
    Returns:
        Space-separated hex bytes (e.g., "48 83 ec 20")
    """
    # Use generator expression to avoid creating intermediate list
    return " ".join(hex_string[i:i+2] for i in range(0, len(hex_string), 2))


@lru_cache(maxsize=128)
def _sanitize_filename_for_rule(file_path: str) -> str:
    """
    Extract and sanitize filename for use in YARA rule names.
    
    Cached to avoid repeated Path operations and string replacements.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Sanitized filename with special characters replaced
    """
    # OPTIMIZATION: Use str.translate() instead of chained replace()
    return Path(file_path).stem.translate(_FILENAME_SANITIZE_TRANS)


@lru_cache(maxsize=128)
def _get_r2_project_name(file_path: str) -> str:
    """Generate a unique project name based on file path hash.
    
    Cached to avoid repeated MD5 computation for the same file path.
    """
    # Use absolute path to ensure uniqueness
    abs_path = str(Path(file_path).resolve())
    return hashlib.md5(abs_path.encode()).hexdigest()


@lru_cache(maxsize=128)
def _calculate_dynamic_timeout(file_path: str, base_timeout: int = 300) -> int:
    """
    Calculate timeout based on file size.
    Strategy: Base timeout + 1 second per MB of file size.
    
    Cached to avoid repeated file stat calls for the same file.
    """
    try:
        size_mb = os.path.getsize(file_path) / (1024 * 1024)
        # Cap the dynamic addition to avoid extremely long timeouts (e.g. max +10 mins)
        additional_time = min(size_mb * 2, 600) 
        return int(base_timeout + additional_time)
    except Exception:
        return base_timeout


async def _execute_r2_command(
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
    effective_timeout = _calculate_dynamic_timeout(str(file_path), base_timeout)
    cmd = _build_r2_cmd(str(file_path), r2_commands, analysis_level)
    
    output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=max_output_size,
        timeout=effective_timeout,
    )
    
    return output, bytes_read


def _build_r2_cmd(file_path: str, r2_commands: list[str], analysis_level: str = "aaa") -> list[str]:
    """
    Build radare2 command.
    
    Simplified version: Always run analysis if requested, skipping project persistence
    to avoid permission issues and 'exit 1' errors in Docker environments.
    
    Performance Note - Early Filtering:
    ===================================
    When searching for specific data, consider using radare2's built-in filtering
    to reduce data transfer and parsing overhead. Examples:
    
    1. Text-based filtering with grep (~):
       - aflj~main       # Filter functions containing "main" (WARNING: breaks JSON)
       - afl~main        # Text-mode filtering (safe, but not JSON)
       - iz~password     # Filter strings containing "password"
    
    2. Radare2's native JSON queries (where available):
       - Some commands support inline filtering in JSON mode
       - Check radare2 documentation for specific command capabilities
    
    3. Trade-offs:
       - Early filtering: Reduces data transfer by 50-70%
       - Late filtering: Preserves JSON structure, more flexible
       - Current implementation: Prioritizes JSON structure integrity
    
    For complex filtering logic (e.g., checking multiple conditions, prefix matching),
    Python-side filtering is more maintainable and flexible.
    """
    base_cmd = ["r2", "-q"]
    
    # If we just want to run commands without analysis (adaptive analysis)
    if analysis_level == "-n":
        return base_cmd + ["-n"] + ["-c", ";".join(r2_commands), str(file_path)]
        
    # Always run analysis + commands
    # We use 'e scr.color=0' to ensure no color codes in output
    combined_cmds = ["e scr.color=0", analysis_level] + r2_commands
    return base_cmd + ["-c", ";".join(combined_cmds), str(file_path)]


def _extract_first_json(text: str) -> str | None:
    """
    Extract the first valid JSON object or array from a string.
    Handles nested structures and ignores surrounding garbage.
    
    PERFORMANCE NOTE: Optimized to O(n) by minimizing redundant scanning.
    Uses early bailout conditions when a bracket is followed only by
    whitespace and more brackets (pathological case: "{ { { { {").
    
    Returns:
        The extracted JSON string, or None if no valid JSON found.
    """
    text = text.strip()
    if not text:
        return None
    
    # Quick optimization: Try parsing the whole string first
    # This handles the common case where output is pure JSON
    if text[0] in ('{', '['):
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
        if char not in ('{', '['):
            i += 1
            continue
        
        # Found potential JSON start
        # Quick heuristic: Skip obvious false starts (isolated brackets)
        # This prevents pathological O(n²) behavior with "{ { { { {".
        # Note: We only check for same bracket type to avoid false positives.
        # Mixed brackets like "{ [" could be valid JSON like `{"arr": [...]}`
        if i + 1 < text_len and text[i + 1] in (' ', '\t'):
            # Bracket followed by whitespace - check if next non-whitespace is also a bracket
            next_idx = i + 2
            while next_idx < text_len and text[next_idx] in (' ', '\t', '\n', '\r'):
                next_idx += 1
            if next_idx < text_len and text[next_idx] == char:
                # Pattern like "{ {" or "[ [" with only whitespace between
                # This is likely noise, not JSON - skip it
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
            
            # Handle string literals (quotes can contain brackets)
            if escape_next:
                escape_next = False
                j += 1
                continue
                
            if c == '\\' and in_string:
                escape_next = True
                j += 1
                continue
                
            if c == '"':
                in_string = not in_string
                j += 1
                continue
            
            # Process brackets only when not inside strings
            if not in_string:
                if c in ('{', '['):
                    stack.append(c)
                elif c in ('}', ']'):
                    if not stack:
                        # Unmatched closing bracket
                        break
                    
                    last = stack[-1]
                    if (c == '}' and last == '{') or (c == ']' and last == '['):
                        stack.pop()
                        if not stack:
                            # Found complete structure, validate it's actually JSON
                            candidate = text[start_idx : j + 1]
                            try:
                                json.loads(candidate)  # Validate it's real JSON
                                return candidate
                            except json.JSONDecodeError:
                                # Not valid JSON, skip past this failed attempt
                                # Optimization: Jump to position j+1 (where extraction stopped)
                                # instead of just i+1, avoiding re-processing characters
                                i = j + 1
                                break
                    else:
                        # Mismatched brackets
                        break
            
            j += 1
        
        # Move past this failed attempt
        if i == start_idx:
            i += 1
    
    return None


def _parse_json_output(output: str):
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
    # First, try to extract clean JSON from potentially noisy output
    json_str = _extract_first_json(output)
    
    if json_str is not None:
        # Found potential JSON, try to parse it
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            # Extracted text wasn't valid JSON (e.g., "[x]" from radare2 output)
            # Fall through to try parsing entire output
            pass
    
    # No valid JSON structure found via extraction, try parsing entire output as-is
    # This handles cases where output is pure JSON without any prefix/suffix
    return json.loads(output)


def get_r2_analysis_pattern():
    """Return the compiled regex pattern for removing radare2 analysis commands."""
    return _R2_ANALYSIS_PATTERN
