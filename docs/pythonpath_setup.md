# PythonPATH Configuration Guide

When you launch the Reversecore MCP server locally, Python must be able to resolve the `reversecore_mcp` package. Add the project root to `PYTHONPATH` to ensure imports succeed.

## Windows (Cursor / Claude Desktop)
1. Open `C:\Users\<USER>\.cursor\mcp.json`.
2. In the `reversecore` entry, confirm the `env` block contains:
   ```json
   "PYTHONPATH": "E:\\\\Reversecore_MCP"
   ```
3. Save the file and re-initiate the MCP connection in Claude Desktop or Cursor.

## macOS / Linux
1. Edit `~/.cursor/mcp.json`.
2. In the `reversecore` entry, add your absolute project path:
   ```json
   "PYTHONPATH": "/ABSOLUTE/PATH/TO/Reversecore_MCP"
   ```
3. Save and restart the MCP client or reconnect.

## Notes
- Always provide the **absolute path to the project root** in `PYTHONPATH`.
- If you use a virtual environment, consider pointing the `command` to the venv’s `python` executable to avoid dependency conflicts.
- For Docker-based workflows, set `PYTHONPATH` inside the container (e.g., in the Dockerfile or via `docker run -e PYTHONPATH=...`).


