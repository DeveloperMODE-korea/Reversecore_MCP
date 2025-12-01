import os
import sys

from reversecore_mcp.core.loader import PluginLoader


def verify_plugins():
    print("Verifying Plugin Architecture...")

    # Initialize loader
    loader = PluginLoader()

    # Path to tools directory
    tools_dir = os.path.join(os.getcwd(), "reversecore_mcp", "tools")
    print(f"Searching for plugins in: {tools_dir}")

    # Discover plugins
    plugins = loader.discover_plugins(tools_dir, "reversecore_mcp.tools")

    print(f"\nFound {len(plugins)} plugins:")
    for plugin in plugins:
        print(f"  - {plugin.name}: {plugin.description}")

    # Expected plugins
    expected_plugins = {
        "r2_analysis",
        "decompilation",
        "static_analysis",
        "file_operations",
        "signature_tools",
        "diff_tools",
        "trinity_defense",
        "ghost_trace",
        "neural_decompiler",
        "adaptive_vaccine",
        "lib_tools",
    }

    found_plugin_names = {p.name for p in plugins}

    missing = expected_plugins - found_plugin_names
    if missing:
        print(f"\n❌ Missing plugins: {missing}")
        sys.exit(1)

    unexpected = found_plugin_names - expected_plugins
    if unexpected:
        print(f"\n⚠️ Unexpected plugins found: {unexpected}")

    print("\n✅ All expected plugins found!")

    # Test registration (mock mcp)
    print("\nTesting registration...")

    class MockMCP:
        def tool(self, func):
            print(f"    Registered tool: {func.__name__}")

    mock_mcp = MockMCP()
    for plugin in plugins:
        print(f"  Registering {plugin.name}...")
        try:
            plugin.register(mock_mcp)
        except Exception as e:
            print(f"  ❌ Failed to register {plugin.name}: {e}")
            sys.exit(1)

    print("\n✅ All plugins registered successfully!")


if __name__ == "__main__":
    verify_plugins()
