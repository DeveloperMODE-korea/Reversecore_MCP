# Reversecore_MCP

An MCP (Model Context Protocol) server that enables AI agents to perform reverse engineering tasks through natural language commands. This server wraps common reverse engineering CLI tools and Python libraries, making them accessible to AI assistants for automated triage and analysis workflows.

## Overview

Reversecore_MCP provides a standardized interface for AI agents to interact with reverse engineering tools such as:
- **CLI Tools**: `strings`, `radare2`
- **Python Libraries**: `yara-python`, `capstone`

The server handles security, error handling, and performance optimization (streaming, output limits) automatically, allowing AI agents to focus on analysis rather than tool management.

## Architecture

### Project Structure

```
Reversecore_MCP/
├── reversecore_mcp/
│   ├── __init__.py
│   ├── server.py              # FastMCP server initialization
│   ├── tools/                 # Tool definitions
│   │   ├── __init__.py
│   │   ├── cli_tools.py       # CLI tool wrappers
│   │   └── lib_tools.py       # Library wrappers
│   └── core/                  # Core utilities
│       ├── __init__.py
│       ├── security.py        # Input validation
│       ├── execution.py       # Safe subprocess execution
│       └── exceptions.py      # Custom exceptions
├── Dockerfile                 # Containerized deployment
├── requirements.txt           # Python dependencies
└── README.md
```

### Design Principles

#### 1. Modularity
- Tools are organized by category (CLI vs. library) in separate modules
- Each tool module exports a registration function that registers tools with the FastMCP server
- `server.py` acts as the central registration point, importing and registering all tool modules

#### 2. Security First
- **No `shell=True`**: All subprocess calls use list-based arguments, never shell commands
- **No `shlex.quote()` on list arguments**: When using `subprocess.run(["cmd", arg1, arg2])`, arguments are passed directly to the process without shell interpretation, so quoting is unnecessary and would break commands
- **Input validation**: File paths and command strings are validated before use
- **Path resolution**: All file paths are resolved to absolute paths to prevent directory traversal

#### 3. Robustness
- Comprehensive error handling: All tool functions catch exceptions and return user-friendly error messages
- Never raise unhandled exceptions to the MCP layer
- Graceful degradation: Tools return error strings instead of crashing

#### 4. Performance
- **Streaming output**: Large outputs are streamed in chunks to prevent OOM
- **Configurable limits**: Output size and execution time limits are configurable per tool
- **Truncation warnings**: When output is truncated, a warning is included in the response

## Technical Decisions

### Security: Command Injection Prevention

**Decision**: Do NOT use `shlex.quote()` when passing arguments as a list to `subprocess.run()`.

**Rationale**:
- When using `subprocess.run(["r2", "-q", "-c", r2_command, file_path])`, arguments are passed directly to the process without shell interpretation
- `shlex.quote()` is only needed when constructing shell commands (with `shell=True`)
- Using `shlex.quote()` on list arguments would break commands like `"pdf @ main"` by adding quotes that radare2 would interpret literally
- **Best Practice**: Always use list arguments, never `shell=True`, validate and sanitize user input at the application layer

**Implementation**:
- All subprocess calls use list-based arguments
- Input validation functions in `core/security.py` validate file paths and command strings
- File paths are resolved to absolute paths and checked against allowed directories (if configured)

### Scalability: FastMCP Modular Architecture

**Decision**: Use registration functions pattern for tool organization.

**Rationale**:
- FastMCP does not have a router system like FastAPI's APIRouter
- FastMCP supports `MCPMixin` for component-based organization, but a simpler pattern is sufficient for this use case
- Each tool module exports a `register_*_tools(mcp: FastMCP)` function that registers all tools in that module

**Implementation Pattern**:
```python
# tools/cli_tools.py
def register_cli_tools(mcp: FastMCP) -> None:
    mcp.tool(run_strings)
    mcp.tool(run_radare2)

# server.py
from reversecore_mcp.tools import cli_tools, lib_tools

mcp = FastMCP(name="Reversecore_MCP")
cli_tools.register_cli_tools(mcp)
lib_tools.register_lib_tools(mcp)
```

### Performance: Large Output Handling

**Decision**: Implement streaming subprocess execution with configurable output limits.

**Rationale**:
- Large files (GB-scale) can cause OOM when using `capture_output=True`
- Need to support both streaming (for large outputs) and full capture (for small outputs)
- Should provide configurable max output size limits

**Implementation**:
- `core/execution.py` provides `execute_subprocess_streaming()` function
- Uses `subprocess.Popen` with `stdout=subprocess.PIPE`
- Reads output in 8KB chunks with size limits
- Returns truncated output with warning when limit is reached
- Tools like `run_strings` accept `max_output_size` parameter

### Dependencies: Version Management Strategy

**Decision**: Use Dockerfile with pinned package versions + r2pipe for radare2 integration.

**Rationale**:
- **Subprocess approach**: Simple but fragile - CLI output format changes between versions
- **r2pipe approach**: More stable API, better error handling, structured data access
- **Hybrid approach**: Use r2pipe for radare2 (primary), keep subprocess as fallback
- Pin versions in Dockerfile to ensure reproducibility

**Implementation**:
- Dockerfile installs system packages from Debian repos (latest stable versions)
- Python dependencies are specified in `requirements.txt` with version constraints
- `r2pipe` is used for radare2 operations (when implemented)
- Subprocess-based radare2 wrapper is kept as fallback

## Installation

### Using Docker (Recommended)

```bash
# Build the Docker image
docker build -t reversecore-mcp .

# Run the server
docker run -it reversecore-mcp
```

### Local Installation

1. Install system dependencies:
   ```bash
   # On Debian/Ubuntu
   sudo apt-get install radare2 yara libyara-dev binutils
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the server:
   ```bash
   python -m reversecore_mcp.server
   ```

## Usage

The server runs as an MCP server using stdio transport by default. Configure your MCP client to connect to the server.

### Example Tool Calls

#### Extract strings from a binary
```json
{
  "tool": "run_strings",
  "arguments": {
    "file_path": "/path/to/binary.exe",
    "min_length": 4,
    "max_output_size": 10000000
  }
}
```

#### Disassemble with radare2
```json
{
  "tool": "run_radare2",
  "arguments": {
    "file_path": "/path/to/binary.exe",
    "r2_command": "pdf @ main"
  }
}
```

#### Scan with YARA
```json
{
  "tool": "run_yara",
  "arguments": {
    "file_path": "/path/to/sample.exe",
    "rule_file": "/path/to/rules.yar"
  }
}
```

## Available Tools

### CLI Tools

- **`run_strings`**: Extract printable strings from binary files
- **`run_radare2`**: Execute radare2 commands on binary files

### Library Tools

- **`run_yara`**: Scan files using YARA rules
- **`disassemble_with_capstone`**: Disassemble binary code using Capstone

## Error Handling

All tools return error messages as strings instead of raising exceptions. Error messages are formatted for AI consumption and include:
- Tool not found errors
- Timeout errors
- Invalid input errors
- Command execution failures

## Development

### Adding New Tools

1. Create a tool function in the appropriate module (`cli_tools.py` or `lib_tools.py`)
2. Add the tool registration in the module's `register_*_tools()` function
3. The tool will be automatically registered when the server starts

### Testing

```bash
# Run tests (when implemented)
pytest tests/
```

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions are welcome! Please ensure that:
- All subprocess calls use list-based arguments (never `shell=True`)
- All tools handle errors gracefully and return error strings
- New tools follow the existing patterns for security and error handling

