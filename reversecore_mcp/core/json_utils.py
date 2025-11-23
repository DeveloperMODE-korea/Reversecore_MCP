"""
High-performance JSON utilities with orjson fallback.

This module provides a drop-in replacement for the standard json module
with automatic fallback. It uses orjson when available for 3-5x faster
JSON parsing and serialization, falling back to the standard json module
if orjson is not installed.

Performance comparison:
- orjson.loads(): ~3-5x faster than json.loads()
- orjson.dumps(): ~3-5x faster than json.dumps()
- Particularly impactful for large JSON objects and hot paths
"""

import json as _stdlib_json
from typing import Any, Optional, Union

try:
    import orjson
    
    _ORJSON_AVAILABLE = True
    
    def loads(s: Union[str, bytes]) -> Any:
        """
        Parse JSON with orjson (fast path).
        
        Args:
            s: JSON string or bytes to parse
            
        Returns:
            Parsed Python object
        """
        if isinstance(s, str):
            s = s.encode('utf-8')
        return orjson.loads(s)
    
    def dumps(obj: Any, indent: Optional[int] = None) -> str:
        """
        Serialize object to JSON with orjson (fast path).
        
        Args:
            obj: Python object to serialize
            indent: If provided, pretty-print with indentation
            
        Returns:
            JSON string
        """
        if indent is not None:
            # orjson uses OPT_INDENT_2 flag for pretty printing
            result = orjson.dumps(obj, option=orjson.OPT_INDENT_2)
        else:
            result = orjson.dumps(obj)
        
        # orjson returns bytes, convert to str for compatibility
        return result.decode('utf-8')
    
except ImportError:
    # Fallback to standard library json
    _ORJSON_AVAILABLE = False
    
    def loads(s: Union[str, bytes]) -> Any:
        """
        Parse JSON with standard library (fallback).
        
        Args:
            s: JSON string or bytes to parse
            
        Returns:
            Parsed Python object
        """
        if isinstance(s, bytes):
            s = s.decode('utf-8')
        return _stdlib_json.loads(s)
    
    def dumps(obj: Any, indent: Optional[int] = None) -> str:
        """
        Serialize object to JSON with standard library (fallback).
        
        Args:
            obj: Python object to serialize
            indent: If provided, pretty-print with indentation
            
        Returns:
            JSON string
        """
        return _stdlib_json.dumps(obj, indent=indent)


def is_orjson_available() -> bool:
    """
    Check if orjson is available.
    
    Returns:
        True if orjson is installed and being used, False if using fallback
    """
    return _ORJSON_AVAILABLE


# For compatibility, expose the same interface as json module
__all__ = ['loads', 'dumps', 'is_orjson_available']
