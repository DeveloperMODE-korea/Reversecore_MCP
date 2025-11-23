"""
Resource Manager for Reversecore_MCP.

This module handles periodic cleanup of temporary files and stale cache entries
to prevent resource exhaustion over time.
"""

import asyncio
import time
import shutil
from pathlib import Path
from typing import Optional

from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.binary_cache import binary_cache
from reversecore_mcp.core.r2_pool import r2_pool

logger = get_logger(__name__)


class ResourceManager:
    """
    Manages background cleanup tasks.
    """
    
    def __init__(self, cleanup_interval: int = 3600): # Default: 1 hour
        self.cleanup_interval = cleanup_interval
        self._task: Optional[asyncio.Task] = None
        self._running = False
        
    async def start(self):
        """Start the background cleanup task."""
        if self._running:
            return
            
        self._running = True
        self._task = asyncio.create_task(self._cleanup_loop())
        logger.info(f"Resource Manager started (interval: {self.cleanup_interval}s)")
        
    async def stop(self):
        """Stop the background cleanup task."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Resource Manager stopped")
        
    async def _cleanup_loop(self):
        """Main cleanup loop."""
        while self._running:
            try:
                await asyncio.sleep(self.cleanup_interval)
                await self.cleanup()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
                
    async def cleanup(self):
        """Perform cleanup operations."""
        logger.info("Starting periodic resource cleanup...")
        
        # 1. Clear stale binary cache
        # (BinaryMetadataCache already checks mtime, but we can clear old entries if needed)
        # For now, we just log.
        # binary_cache.clear() # Too aggressive?
        
        # 2. Clean up temporary files
        config = get_config()
        workspace = config.workspace
        
        try:
            # Clean .tmp files older than 24 hours
            now = time.time()
            max_age = 24 * 3600
            
            cleaned_count = 0
            
            # List of patterns to clean
            patterns = ["*.tmp", ".r2_*", "*.r2"]
            
            for pattern in patterns:
                for temp_file in workspace.glob(pattern):
                    try:
                        if temp_file.is_file():
                            mtime = temp_file.stat().st_mtime
                            if now - mtime > max_age:
                                temp_file.unlink()
                                cleaned_count += 1
                    except Exception:
                        pass
                        
            if cleaned_count > 0:
                logger.info(f"Cleaned up {cleaned_count} stale temporary files")
                
        except Exception as e:
            logger.error(f"Failed to clean temp files: {e}")
            
        # 3. Check r2_pool health?
        # r2_pool manages itself via LRU.
        
        logger.info("Resource cleanup complete")


# Global instance
resource_manager = ResourceManager()
