"""
Plugin interface definition for Reversecore MCP.

This module defines the contract that all plugins must adhere to.
"""

from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel


class Tool(BaseModel):
    """Wrapper for an MCP tool function."""

    name: str
    description: str
    func: Callable
    parameters: dict | None = None  # Optional schema override


class Plugin(ABC):
    """Abstract base class for all plugins."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the unique name of the plugin."""
        pass

    @property
    def description(self) -> str:
        """Return a brief description of the plugin."""
        return ""

    @abstractmethod
    def register(self, mcp_server: Any) -> None:
        """
        Register tools with the MCP server.

        Args:
            mcp_server: The FastMCP server instance
        """
        pass
