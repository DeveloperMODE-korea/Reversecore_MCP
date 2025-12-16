"""
Patch Explainer module - Backward compatibility alias.

This module was moved to common/patch_explainer.
"""

# Re-export everything from common.patch_explainer
from reversecore_mcp.tools.common.patch_explainer import *
from reversecore_mcp.tools.common.patch_explainer import (
    explain_patch,
    _generate_explanation,
    _generate_diff_snippet,
)

__all__ = [
    "explain_patch",
    "_generate_explanation",
    "_generate_diff_snippet",
]
