# Quick Start

This guide will help you get started with Reversecore MCP in minutes.

## Step 1: Start the Server

### Using Docker

```bash
docker run -v $(pwd)/samples:/app/workspace \
  ghcr.io/yourusername/reversecore_mcp:latest
```

### From Source

```bash
export REVERSECORE_WORKSPACE=./samples
python server.py
```

## Step 2: Connect Your AI Assistant

### Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "reversecore": {
      "command": "python",
      "args": ["/path/to/Reversecore_MCP/server.py"],
      "env": {
        "REVERSECORE_WORKSPACE": "/path/to/workspace"
      }
    }
  }
}
```

### HTTP Mode

For remote AI agents, use HTTP transport:

```bash
export MCP_TRANSPORT=http
export MCP_API_KEY=your-secret-key
python server.py
```

Then connect to `http://localhost:8000/mcp`.

## Step 3: Analyze a Binary

Once connected, ask your AI assistant to analyze a binary:

> "Analyze the binary at /app/workspace/sample.exe and tell me about its functions"

The AI will use Reversecore MCP tools to:

1. Parse the binary metadata
2. List functions and their addresses
3. Decompile interesting functions
4. Identify potential threats

## Example Prompts

### Basic Analysis

> "What type of file is sample.bin?"

### Function Analysis

> "List all functions in malware.exe"

### Decompilation

> "Decompile the main function of app.exe"

### Threat Detection

> "Run Ghost Trace on suspicious.bin to find hidden behaviors"

### YARA Signature

> "Generate a YARA signature for the malicious function at 0x401000"

## Next Steps

- Read the [User Guide](../user-guide/overview.md) for detailed usage
- Explore the [API Reference](../api/core/config.md) for tool documentation
- Check [Configuration](configuration.md) for advanced setup
