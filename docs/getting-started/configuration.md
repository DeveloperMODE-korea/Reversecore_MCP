# Configuration

Reversecore MCP is configured through environment variables for flexibility in different deployment environments.

## Environment Variables

### Workspace Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `REVERSECORE_WORKSPACE` | Current directory | Path to workspace directory for file operations |
| `REVERSECORE_READ_DIRS` | Empty | Comma-separated list of read-only directories |
| `REVERSECORE_STRICT_PATHS` | `false` | Enable strict path validation |

### Logging Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `INFO` | Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL |
| `LOG_FORMAT` | `human` | Log format: `human` for readable, `json` for structured |
| `LOG_FILE` | `/tmp/reversecore/app.log` | Path to log file |

### Server Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_TRANSPORT` | `stdio` | Transport mode: `stdio` or `http` |
| `MCP_API_KEY` | Empty | API key for HTTP mode authentication |
| `RATE_LIMIT` | `60` | Rate limit (requests per minute) |

### Tool Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DEFAULT_TOOL_TIMEOUT` | `120` | Default timeout for tool execution (seconds) |
| `LIEF_MAX_FILE_SIZE` | `1000000000` | Maximum file size for LIEF parsing (bytes) |

### R2 Pool Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `REVERSECORE_R2_POOL_SIZE` | `3` | Number of radare2 connections in pool |
| `REVERSECORE_R2_POOL_TIMEOUT` | `30` | Timeout for acquiring connection from pool |

## Example Configurations

### Development

```bash
export REVERSECORE_WORKSPACE=./workspace
export LOG_LEVEL=DEBUG
export LOG_FORMAT=human
export MCP_TRANSPORT=stdio
```

### Production (HTTP Mode)

```bash
export REVERSECORE_WORKSPACE=/data/workspace
export REVERSECORE_STRICT_PATHS=true
export LOG_LEVEL=INFO
export LOG_FORMAT=json
export MCP_TRANSPORT=http
export MCP_API_KEY=your-secret-api-key
export RATE_LIMIT=100
```

### Docker Compose

```yaml
version: '3.8'
services:
  reversecore:
    image: ghcr.io/yourusername/reversecore_mcp:latest
    environment:
      - REVERSECORE_WORKSPACE=/app/workspace
      - LOG_LEVEL=INFO
      - LOG_FORMAT=json
      - MCP_TRANSPORT=http
    volumes:
      - ./workspace:/app/workspace
    ports:
      - "8000:8000"
```

## Using .env File

Create a `.env` file in the project root:

```bash
# .env
REVERSECORE_WORKSPACE=/path/to/workspace
LOG_LEVEL=INFO
LOG_FORMAT=json
MCP_TRANSPORT=http
MCP_API_KEY=your-secret-key
```

The configuration will be automatically loaded from this file.
