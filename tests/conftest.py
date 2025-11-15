"""
Pytest configuration and shared fixtures.
"""

import os
from pathlib import Path

import pytest

from reversecore_mcp.core.config import reset_config


# Set test environment variables (will be overridden by individual tests)
os.environ["LOG_LEVEL"] = "INFO"


@pytest.fixture(autouse=True)
def reset_workspace_env(monkeypatch, tmp_path):
    """Automatically set workspace environment for each test using tmp_path."""
    workspace = tmp_path / "workspace"
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(exist_ok=True)

    monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace))
    monkeypatch.setenv("REVERSECORE_READ_DIRS", str(rules_dir))

    reset_config()
    return workspace


@pytest.fixture
def workspace_dir(tmp_path):
    """Create a temporary workspace directory for tests."""
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    return workspace


@pytest.fixture
def sample_binary_path(workspace_dir, monkeypatch):
    """Create a simple test binary file."""
    # Ensure workspace env is set for this test
    monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace_dir))

    binary_path = workspace_dir / "test_binary.bin"
    # Create a simple binary with some data
    binary_path.write_bytes(b"\x00\x01\x02\x03Hello World\x00")
    return str(binary_path)

