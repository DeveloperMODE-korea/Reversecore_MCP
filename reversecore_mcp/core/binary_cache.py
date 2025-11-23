"""
Binary Metadata Cache

This module provides caching for binary analysis results.
It prevents redundant analysis of the same files.
"""

import hashlib
import time
import asyncio
from typing import Dict, Any, Optional
from pathlib import Path

from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import metrics_collector

logger = get_logger(__name__)


class BinaryMetadataCache:
    """
    Caches metadata for analyzed binaries.
    
    Keyed by file path and modification time (or hash).
    """
    
    def __init__(self):
        self._cache: Dict[str, Any] = {}
        self._file_timestamps: Dict[str, float] = {}

    def _get_cache_key(self, file_path: str) -> str:
        """Generate a cache key based on file path."""
        return str(Path(file_path).absolute())

    def _is_valid(self, file_path: str) -> bool:
        """Check if cache entry is valid (file hasn't changed)."""
        key = self._get_cache_key(file_path)
        if key not in self._cache:
            return False
            
        try:
            mtime = Path(file_path).stat().st_mtime
            return self._file_timestamps.get(key) == mtime
        except FileNotFoundError:
            return False

    def get(self, file_path: str, key: str) -> Optional[Any]:
        """Get a specific metadata item for a file."""
        cache_key = self._get_cache_key(file_path)
        if self._is_valid(file_path):
            val = self._cache[cache_key].get(key)
            if val is not None:
                metrics_collector.record_cache_hit("binary_cache")
                return val
        
        metrics_collector.record_cache_miss("binary_cache")
        return None

    def set(self, file_path: str, key: str, value: Any):
        """Set a specific metadata item for a file."""
        cache_key = self._get_cache_key(file_path)
        
        # Initialize if needed
        if cache_key not in self._cache:
            self._cache[cache_key] = {}
            
        # Update timestamp
        try:
            self._file_timestamps[cache_key] = Path(file_path).stat().st_mtime
        except FileNotFoundError:
            pass
            
        self._cache[cache_key][key] = value
        logger.debug(f"Cached {key} for {file_path}")

    def clear(self, file_path: str = None):
        """Clear cache for a specific file or all files."""
        if file_path:
            key = self._get_cache_key(file_path)
            if key in self._cache:
                del self._cache[key]
            if key in self._file_timestamps:
                del self._file_timestamps[key]
        else:
            self._cache.clear()
            self._file_timestamps.clear()


# Global instance
binary_cache = BinaryMetadataCache()
