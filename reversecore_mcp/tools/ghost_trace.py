"""
Ghost Trace module - Backward compatibility alias.

This module was renamed to dormant_detector.
All imports should work transparently.
"""

# Re-export everything from dormant_detector
from reversecore_mcp.tools.malware.dormant_detector import *
from reversecore_mcp.tools.malware.dormant_detector import (
    dormant_detector,
    ghost_trace,
    register_dormant_detector,
    register_ghost_trace,
    _extract_json_safely,
    _validate_r2_identifier,
    _get_file_cache_key,
    _run_r2_cmd,
    _find_orphan_functions,
    _identify_conditional_paths,
    _verify_hypothesis_with_emulation,
)

# For backward compatibility
__all__ = [
    "dormant_detector",
    "ghost_trace",
    "register_dormant_detector",
    "register_ghost_trace",
    "_extract_json_safely",
    "_validate_r2_identifier",
    "_get_file_cache_key",
]
