#!/usr/bin/env python3
"""Temporary script to fix imports after refactoring."""

import sys

file_path = sys.argv[1]

with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Replace imports
content = content.replace(
    'from reversecore_mcp.tools.cli_tools import trace_execution_path',
    'from reversecore_mcp.tools.r2_analysis import trace_execution_path'
)
content = content.replace(
    "'reversecore_mcp.tools.cli_tools.validate_file_path'",
    "'reversecore_mcp.core.security.validate_file_path'"
)
content = content.replace(
    "'reversecore_mcp.tools.cli_tools._build_r2_cmd'",
    "'reversecore_mcp.tools.r2_analysis._build_r2_cmd'"
)
content = content.replace(
    "'reversecore_mcp.tools.cli_tools.execute_subprocess_async'",
    "'reversecore_mcp.tools.r2_analysis.execute_subprocess_async'"
)

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)

print(f"Fixed imports in {file_path}")
