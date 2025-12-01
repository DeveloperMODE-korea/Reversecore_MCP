"""Unit tests for R2ConnectionPool."""

from unittest.mock import Mock, patch

import pytest

from reversecore_mcp.core.r2_pool import R2ConnectionPool, r2_pool


class TestR2ConnectionPool:
    """Tests for R2ConnectionPool class."""

    def test_init(self):
        """Test pool initialization."""
        pool = R2ConnectionPool(max_connections=5)
        assert pool.max_connections == 5
        assert len(pool._pool) == 0

    @patch("reversecore_mcp.core.r2_pool.r2pipe")
    def test_get_connection_creates_new(self, mock_r2pipe):
        """Test that get_connection creates a new connection."""
        mock_r2 = Mock()
        mock_r2pipe.open.return_value = mock_r2

        pool = R2ConnectionPool(max_connections=5)
        result = pool.get_connection("/test/file.bin")

        assert result == mock_r2
        mock_r2pipe.open.assert_called_once_with("/test/file.bin", flags=["-2"])

    @patch("reversecore_mcp.core.r2_pool.r2pipe")
    def test_get_connection_reuses_existing(self, mock_r2pipe):
        """Test that get_connection reuses existing connections."""
        mock_r2 = Mock()
        mock_r2pipe.open.return_value = mock_r2

        pool = R2ConnectionPool(max_connections=5)

        # First call creates connection
        result1 = pool.get_connection("/test/file.bin")
        # Second call reuses connection
        result2 = pool.get_connection("/test/file.bin")

        assert result1 == result2
        # open should only be called once
        assert mock_r2pipe.open.call_count == 1

    @patch("reversecore_mcp.core.r2_pool.r2pipe")
    def test_eviction_on_max_connections(self, mock_r2pipe):
        """Test that oldest connection is evicted when max is reached."""
        mock_r2_list = [Mock() for _ in range(3)]
        mock_r2pipe.open.side_effect = mock_r2_list

        pool = R2ConnectionPool(max_connections=2)

        # Create 3 connections, should evict the first
        pool.get_connection("/test/file1.bin")
        pool.get_connection("/test/file2.bin")
        pool.get_connection("/test/file3.bin")

        # First connection should be evicted and quit should be called
        mock_r2_list[0].quit.assert_called_once()

        # Pool should contain only 2 connections
        assert len(pool._pool) == 2

    @patch("reversecore_mcp.core.r2_pool.r2pipe")
    def test_execute_command(self, mock_r2pipe):
        """Test executing a command."""
        mock_r2 = Mock()
        mock_r2.cmd.return_value = "command output"
        mock_r2pipe.open.return_value = mock_r2

        pool = R2ConnectionPool(max_connections=5)
        result = pool.execute("/test/file.bin", "pdf @ main")

        assert result == "command output"
        mock_r2.cmd.assert_called_once_with("pdf @ main")

    @patch("reversecore_mcp.core.r2_pool.r2pipe")
    def test_execute_retries_on_failure(self, mock_r2pipe):
        """Test that execute retries once on failure."""
        mock_r2_first = Mock()
        mock_r2_first.cmd.side_effect = Exception("Connection lost")

        mock_r2_second = Mock()
        mock_r2_second.cmd.return_value = "success"

        mock_r2pipe.open.side_effect = [mock_r2_first, mock_r2_second]

        pool = R2ConnectionPool(max_connections=5)
        result = pool.execute("/test/file.bin", "pdf @ main")

        assert result == "success"
        # Should have tried twice
        assert mock_r2pipe.open.call_count == 2

    @patch("reversecore_mcp.core.r2_pool.r2pipe")
    def test_execute_raises_after_retry_failure(self, mock_r2pipe):
        """Test that execute raises after retry fails."""
        mock_r2 = Mock()
        mock_r2.cmd.side_effect = Exception("Connection lost")
        mock_r2pipe.open.return_value = mock_r2

        pool = R2ConnectionPool(max_connections=5)

        with pytest.raises(Exception, match="Connection lost"):
            pool.execute("/test/file.bin", "pdf @ main")

    @patch("reversecore_mcp.core.r2_pool.r2pipe", None)
    def test_get_connection_raises_when_r2pipe_not_installed(self):
        """Test that get_connection raises ImportError when r2pipe is not available."""
        pool = R2ConnectionPool(max_connections=5)

        with pytest.raises(ImportError, match="r2pipe is not installed"):
            pool.get_connection("/test/file.bin")

    @patch("reversecore_mcp.core.r2_pool.r2pipe")
    def test_close_all(self, mock_r2pipe):
        """Test closing all connections."""
        mock_r2_list = [Mock() for _ in range(3)]
        mock_r2pipe.open.side_effect = mock_r2_list

        pool = R2ConnectionPool(max_connections=5)

        # Create connections
        pool.get_connection("/test/file1.bin")
        pool.get_connection("/test/file2.bin")
        pool.get_connection("/test/file3.bin")

        # Close all
        pool.close_all()

        # All should be quit
        for mock_r2 in mock_r2_list:
            mock_r2.quit.assert_called_once()

        # Pool should be empty
        assert len(pool._pool) == 0
        assert len(pool._last_access) == 0

    @patch("reversecore_mcp.core.r2_pool.r2pipe")
    def test_is_analyzed(self, mock_r2pipe):
        """Test checking if a file has been analyzed."""
        mock_r2 = Mock()
        mock_r2pipe.open.return_value = mock_r2

        pool = R2ConnectionPool(max_connections=5)

        # Initially not analyzed
        assert pool.is_analyzed("/test/file.bin") is False

        # Create connection
        pool.get_connection("/test/file.bin")

        # Still not analyzed (just connected)
        assert pool.is_analyzed("/test/file.bin") is False

        # Mark as analyzed
        pool.mark_analyzed("/test/file.bin")

        # Now analyzed
        assert pool.is_analyzed("/test/file.bin") is True

    @patch("reversecore_mcp.core.r2_pool.r2pipe")
    def test_mark_analyzed(self, mock_r2pipe):
        """Test marking a file as analyzed."""
        mock_r2 = Mock()
        mock_r2pipe.open.return_value = mock_r2

        pool = R2ConnectionPool(max_connections=5)

        # Create connection
        pool.get_connection("/test/file.bin")

        # Mark as analyzed
        pool.mark_analyzed("/test/file.bin")

        # Should be in analyzed set
        assert "/test/file.bin" in pool._analyzed_files

    @patch("reversecore_mcp.core.r2_pool.r2pipe")
    def test_eviction_clears_analyzed_flag(self, mock_r2pipe):
        """Test that eviction clears the analyzed flag."""
        mock_r2_list = [Mock() for _ in range(3)]
        mock_r2pipe.open.side_effect = mock_r2_list

        pool = R2ConnectionPool(max_connections=2)

        # Create and mark first file as analyzed
        pool.get_connection("/test/file1.bin")
        pool.mark_analyzed("/test/file1.bin")

        # Create second file
        pool.get_connection("/test/file2.bin")

        # Third file should evict first
        pool.get_connection("/test/file3.bin")

        # First file should no longer be marked as analyzed
        assert pool.is_analyzed("/test/file1.bin") is False

    @patch("reversecore_mcp.core.r2_pool.r2pipe")
    @pytest.mark.asyncio
    async def test_execute_async(self, mock_r2pipe):
        """Test async execution."""
        mock_r2 = Mock()
        mock_r2.cmd.return_value = "async output"
        mock_r2pipe.open.return_value = mock_r2

        pool = R2ConnectionPool(max_connections=5)
        result = await pool.execute_async("/test/file.bin", "pdf @ main")

        assert result == "async output"

    def test_global_instance(self):
        """Test that the global instance is accessible."""
        assert r2_pool is not None
        assert isinstance(r2_pool, R2ConnectionPool)

    @patch("reversecore_mcp.core.r2_pool.r2pipe")
    def test_lru_behavior(self, mock_r2pipe):
        """Test that the pool behaves as LRU cache."""
        mock_r2_list = [Mock() for _ in range(3)]
        mock_r2pipe.open.side_effect = mock_r2_list

        pool = R2ConnectionPool(max_connections=2)

        # Access in order: 1, 2, 1
        pool.get_connection("/test/file1.bin")
        pool.get_connection("/test/file2.bin")
        pool.get_connection("/test/file1.bin")  # Move file1 to end

        # Now add file3, should evict file2 (least recently used)
        pool.get_connection("/test/file3.bin")

        # file2 should be evicted
        mock_r2_list[1].quit.assert_called_once()

        # file1 and file3 should still be in pool
        assert "/test/file1.bin" in pool._pool
        assert "/test/file3.bin" in pool._pool
        assert "/test/file2.bin" not in pool._pool
