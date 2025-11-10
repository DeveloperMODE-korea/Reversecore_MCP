"""
Reversecore_MCP Server

This module initializes the FastMCP server and registers all available tools.
"""

from fastmcp import FastMCP

from reversecore_mcp.tools import cli_tools, lib_tools

# Initialize the FastMCP server
mcp = FastMCP(name="Reversecore_MCP")

# Register all tool modules
cli_tools.register_cli_tools(mcp)
lib_tools.register_lib_tools(mcp)


def main():
    """Run the MCP server."""
    # Use stdio transport for MCP protocol
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

