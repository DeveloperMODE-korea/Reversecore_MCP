"""CLI tool wrappers that return structured ToolResult payloads."""

import json
import re
import shutil
from pathlib import Path

from fastmcp import FastMCP

from reversecore_mcp.core.command_spec import validate_r2_command
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.execution import execute_subprocess_async
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, success
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.core.validators import validate_tool_parameters


def register_cli_tools(mcp: FastMCP) -> None:
    """
    Register all CLI tool wrappers with the FastMCP server.

    Args:
        mcp: The FastMCP server instance to register tools with
    """
    mcp.tool(run_file)
    mcp.tool(run_strings)
    mcp.tool(run_radare2)
    mcp.tool(run_binwalk)
    mcp.tool(copy_to_workspace)
    mcp.tool(list_workspace)
    mcp.tool(generate_function_graph)
    mcp.tool(emulate_machine_code)


@log_execution(tool_name="run_file")
@track_metrics("run_file")
@handle_tool_errors
async def run_file(file_path: str, timeout: int = 30) -> ToolResult:
    """Identify file metadata using the ``file`` CLI utility."""

    validated_path = validate_file_path(file_path)
    cmd = ["file", str(validated_path)]
    output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=1_000_000,
        timeout=timeout,
    )
    return success(output.strip(), bytes_read=bytes_read)


@log_execution(tool_name="run_strings")
@track_metrics("run_strings")
@handle_tool_errors
async def run_strings(
    file_path: str,
    min_length: int = 4,
    max_output_size: int = 10_000_000,
    timeout: int = 300,
) -> ToolResult:
    """Extract printable strings using the ``strings`` CLI."""

    validate_tool_parameters(
        "run_strings",
        {"min_length": min_length, "max_output_size": max_output_size},
    )
    validated_path = validate_file_path(file_path)
    cmd = ["strings", "-n", str(min_length), str(validated_path)]
    output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=max_output_size,
        timeout=timeout,
    )
    return success(output, bytes_read=bytes_read)


@log_execution(tool_name="run_radare2")
@track_metrics("run_radare2")
@handle_tool_errors
async def run_radare2(
    file_path: str,
    r2_command: str,
    max_output_size: int = 10_000_000,
    timeout: int = 300,
) -> ToolResult:
    """Execute vetted radare2 commands for binary triage."""

    validate_tool_parameters("run_radare2", {"r2_command": r2_command})
    validated_path = validate_file_path(file_path)
    validated_command = validate_r2_command(r2_command)
    cmd = ["r2", "-q", "-c", validated_command, str(validated_path)]
    output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=max_output_size,
        timeout=timeout,
    )
    return success(output, bytes_read=bytes_read)


@log_execution(tool_name="run_binwalk")
@track_metrics("run_binwalk")
@handle_tool_errors
async def run_binwalk(
    file_path: str,
    depth: int = 8,
    max_output_size: int = 10_000_000,
    timeout: int = 300,
) -> ToolResult:
    """Analyze binaries for embedded content using binwalk."""

    validated_path = validate_file_path(file_path)
    cmd = ["binwalk", "-A", "-d", str(depth), str(validated_path)]
    output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=max_output_size,
        timeout=timeout,
    )
    return success(output, bytes_read=bytes_read)


@log_execution(tool_name="copy_to_workspace")
@track_metrics("copy_to_workspace")
@handle_tool_errors
def copy_to_workspace(
    source_path: str,
    destination_name: str = None,
) -> ToolResult:
    """
    Copy any accessible file to the workspace directory.

    This tool allows copying files from any location (including AI agent upload directories)
    to the workspace where other reverse engineering tools can access them.

    Supports files from:
    - Claude Desktop uploads (/mnt/user-data/uploads)
    - Cursor uploads
    - Windsurf uploads
    - Local file paths
    - Any other accessible location

    Args:
        source_path: Absolute or relative path to the source file
        destination_name: Optional custom filename in workspace (defaults to original name)

    Returns:
        ToolResult with the new file path in workspace
    """
    from reversecore_mcp.core.config import get_config
    from reversecore_mcp.core.exceptions import ValidationError

    # Convert to Path and resolve (but don't require strict=True for external files)
    try:
        source = Path(source_path).expanduser().resolve()
    except Exception as e:
        raise ValidationError(
            f"Invalid source path: {source_path}",
            details={"source_path": source_path, "error": str(e)},
        )

    # Validate source exists and is a file
    if not source.exists():
        raise ValidationError(
            f"Source file does not exist: {source}",
            details={"source_path": str(source)},
        )

    if not source.is_file():
        raise ValidationError(
            f"Source path is not a file: {source}", details={"source_path": str(source)}
        )

    # Check file size (prevent copying extremely large files)
    max_file_size = 5 * 1024 * 1024 * 1024  # 5GB
    file_size = source.stat().st_size
    if file_size > max_file_size:
        raise ValidationError(
            f"File too large to copy: {file_size} bytes (max: {max_file_size} bytes)",
            details={"file_size": file_size, "max_size": max_file_size},
        )

    # Determine destination filename
    if destination_name:
        # Sanitize destination name (remove path separators and dangerous chars)
        dest_name = Path(destination_name).name
        # Additional sanitization for security - check if sanitization changed the name
        if dest_name != destination_name or not dest_name:
            raise ValidationError(
                f"Invalid destination name: {destination_name}",
                details={"destination_name": destination_name},
            )
    else:
        dest_name = source.name

    # Build destination path in workspace
    config = get_config()
    destination = config.workspace / dest_name

    # Check if file already exists
    if destination.exists():
        raise ValidationError(
            f"File already exists in workspace: {dest_name}",
            details={
                "destination": str(destination),
                "hint": "Use a different destination_name or remove the existing file first",
            },
        )

    # Copy file to workspace
    try:
        shutil.copy2(source, destination)
        copied_size = destination.stat().st_size

        return success(
            str(destination),
            source_path=str(source),
            destination_path=str(destination),
            file_size=copied_size,
            message=f"File copied successfully to workspace: {dest_name}",
        )
    except PermissionError as e:
        raise ValidationError(
            f"Permission denied when copying file: {e}",
            details={"source": str(source), "destination": str(destination)},
        )
    except Exception as e:
        raise ValidationError(
            f"Failed to copy file: {e}",
            details={
                "source": str(source),
                "destination": str(destination),
                "error": str(e),
            },
        )


@log_execution(tool_name="list_workspace")
@track_metrics("list_workspace")
@handle_tool_errors
def list_workspace() -> ToolResult:
    """
    List all files in the workspace directory.

    Returns:
        ToolResult with list of files in workspace
    """
    from reversecore_mcp.core.config import get_config

    config = get_config()
    workspace = config.workspace

    if not workspace.exists():
        return success(
            {"files": [], "message": "Workspace is empty"},
            file_count=0,
            workspace_path=str(workspace),
        )

    files = []
    for item in workspace.iterdir():
        if item.is_file():
            files.append(
                {"name": item.name, "size": item.stat().st_size, "path": str(item)}
            )

    return success(
        {"files": files}, file_count=len(files), workspace_path=str(workspace)
    )


def _radare2_json_to_mermaid(json_str: str) -> str:
    """
    Convert Radare2 'agfj' JSON output to Mermaid Flowchart syntax.
    Optimized for LLM context efficiency.
    
    Args:
        json_str: JSON output from radare2 agfj command
        
    Returns:
        Mermaid flowchart syntax string
    """
    try:
        graph_data = json.loads(json_str)
        if not graph_data:
            return "graph TD;\n    Error[No graph data found]"
            
        # agfj returns list format for function graph
        blocks = graph_data[0].get("blocks", []) if isinstance(graph_data, list) else graph_data.get("blocks", [])
        
        mermaid_lines = ["graph TD"]
        
        for block in blocks:
            # 1. Generate node ID from offset
            node_id = f"N_{hex(block.get('offset', 0))}"
            
            # 2. Generate node label from assembly opcodes
            ops = block.get("ops", [])
            op_codes = [op.get("opcode", "") for op in ops]
            
            # Token efficiency: limit to 5 lines per block
            if len(op_codes) > 5:
                op_codes = op_codes[:5] + ["..."]
            
            # Escape Mermaid special characters
            label_content = "\\n".join(op_codes).replace('"', "'").replace("(", "[").replace(")", "]")
            
            # Define node
            mermaid_lines.append(f'    {node_id}["{label_content}"]')
            
            # 3. Create edges
            # True branch (jump)
            if "jump" in block:
                target_id = f"N_{hex(block['jump'])}"
                mermaid_lines.append(f"    {node_id} -->|True| {target_id}")
                
            # False branch (fail)
            if "fail" in block:
                target_id = f"N_{hex(block['fail'])}"
                mermaid_lines.append(f"    {node_id} -.->|False| {target_id}")
                
        return "\n".join(mermaid_lines)
        
    except Exception as e:
        return f"graph TD;\n    Error[Parse Error: {str(e)}]"


@log_execution(tool_name="generate_function_graph")
@track_metrics("generate_function_graph")
@handle_tool_errors
async def generate_function_graph(
    file_path: str,
    function_address: str,
    format: str = "mermaid",
    timeout: int = 300,
) -> ToolResult:
    """
    Generate a Control Flow Graph (CFG) for a specific function.
    
    This tool uses radare2 to analyze the function structure and returns
    a visualization code (Mermaid by default) that helps AI understand
    the code flow without reading thousands of lines of assembly.

    Args:
        file_path: Path to the binary file (must be in workspace)
        function_address: Function address (e.g., 'main', '0x140001000', 'sym.foo')
        format: Output format ('mermaid', 'json', or 'dot'). Default is 'mermaid'.
        timeout: Execution timeout in seconds
        
    Returns:
        ToolResult with CFG visualization or JSON data
    """
    from reversecore_mcp.core.result import failure
    
    # 1. Parameter validation
    validate_tool_parameters(
        "generate_function_graph", 
        {"function_address": function_address, "format": format}
    )
    validated_path = validate_file_path(file_path)
    
    # 2. Security check for function address (prevent shell injection)
    if not re.match(r'^[a-zA-Z0-9_.]+$', function_address.replace("0x", "")):
        return failure("VALIDATION_ERROR", "Invalid function address format")

    # 3. Build radare2 command
    r2_cmd_str = f"agfj @ {function_address}"
    
    cmd = [
        "r2", 
        "-q", 
        "-c", "aaa",             # Automatic analysis
        "-c", r2_cmd_str,        # Extract graph JSON
        str(validated_path)
    ]

    # 4. Execute subprocess asynchronously
    # Large graphs need higher output limit
    output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=50_000_000, 
        timeout=timeout,
    )

    # 5. Format conversion and return
    if format.lower() == "json":
        return success(output, bytes_read=bytes_read, format="json")
    
    elif format.lower() == "mermaid":
        mermaid_code = _radare2_json_to_mermaid(output)
        return success(
            mermaid_code, 
            bytes_read=bytes_read, 
            format="mermaid",
            description="Render this using Mermaid to see the control flow."
        )
    
    elif format.lower() == "dot":
        # For DOT format, call radare2 with agfd command
        dot_cmd = [
            "r2",
            "-q",
            "-c", "aaa",
            "-c", f"agfd @ {function_address}",
            str(validated_path)
        ]
        dot_output, dot_bytes = await execute_subprocess_async(
            dot_cmd,
            max_output_size=50_000_000,
            timeout=timeout,
        )
        return success(dot_output, bytes_read=dot_bytes, format="dot")
    
    return failure("INVALID_FORMAT", f"Unsupported format: {format}")


def _parse_register_state(ar_output: str) -> dict:
    """
    Parse radare2 'ar' command output into structured register state.
    
    Args:
        ar_output: Raw output from 'ar' command
        
    Returns:
        Dictionary mapping register names to values
        
    Example output from 'ar':
        rax = 0x00000000
        rbx = 0x00401000
        ...
    """
    registers = {}
    
    for line in ar_output.strip().split('\n'):
        if '=' in line:
            parts = line.split('=')
            if len(parts) == 2:
                reg_name = parts[0].strip()
                reg_value = parts[1].strip()
                registers[reg_name] = reg_value
    
    return registers


@log_execution(tool_name="emulate_machine_code")
@track_metrics("emulate_machine_code")
@handle_tool_errors
async def emulate_machine_code(
    file_path: str,
    start_address: str,
    instructions: int = 50,
    timeout: int = 300,
) -> ToolResult:
    """
    Emulate machine code execution using radare2 ESIL (Evaluable Strings Intermediate Language).
    
    This tool provides safe, sandboxed emulation of binary code without actual execution.
    Perfect for analyzing obfuscated code, understanding register states, and predicting
    execution outcomes without security risks.
    
    **Key Use Cases:**
    - De-obfuscation: Reveal hidden strings by emulating XOR/shift operations
    - Register Analysis: See final register values after code execution
    - Safe Malware Analysis: Predict behavior without running malicious code
    
    **Safety Features:**
    - Virtual CPU simulation (no real execution)
    - Instruction count limit (max 1000) prevents infinite loops
    - Memory sandboxing (changes don't affect host system)

    Args:
        file_path: Path to the binary file (must be in workspace)
        start_address: Address to start emulation (e.g., 'main', '0x401000', 'sym.decrypt')
        instructions: Number of instructions to execute (default 50, max 1000)
        timeout: Execution timeout in seconds
        
    Returns:
        ToolResult with register states and emulation summary
    """
    from reversecore_mcp.core.result import failure
    
    # 1. Parameter validation
    validate_tool_parameters(
        "emulate_machine_code",
        {"start_address": start_address, "instructions": instructions}
    )
    validated_path = validate_file_path(file_path)
    
    # 2. Security check for start address (prevent shell injection)
    if not re.match(r'^[a-zA-Z0-9_.]+$', start_address.replace("0x", "")):
        return failure("VALIDATION_ERROR", "Invalid start address format")

    # 3. Build radare2 ESIL emulation command chain
    # Note: Commands must be executed in specific order for ESIL to work correctly
    cmd = [
        "r2",
        "-q",
        "-c", "aaa",                    # Analyze all
        "-c", f"s {start_address}",     # Seek to start address
        "-c", "aei",                    # Initialize ESIL VM
        "-c", "aeim",                   # Initialize ESIL memory (stack)
        "-c", "aeip",                   # Initialize program counter to current seek
        "-c", f"aes {instructions}",   # Step through N instructions
        "-c", "ar",                     # Show all registers
        str(validated_path)
    ]

    # 4. Execute emulation
    try:
        output, bytes_read = await execute_subprocess_async(
            cmd,
            max_output_size=10_000_000,  # Register output is typically small
            timeout=timeout,
        )
        
        # 5. Parse register state
        register_state = _parse_register_state(output)
        
        if not register_state:
            return failure(
                "EMULATION_ERROR",
                "Failed to extract register state from emulation output",
                hint="The binary may not be compatible with ESIL emulation, or the start address is invalid"
            )
        
        # 6. Build result with metadata
        return success(
            register_state,
            bytes_read=bytes_read,
            format="register_state",
            instructions_executed=instructions,
            start_address=start_address,
            description=f"Emulated {instructions} instructions starting at {start_address}"
        )
        
    except Exception as e:
        return failure(
            "EMULATION_ERROR",
            f"ESIL emulation failed: {str(e)}",
            hint="Check that the binary architecture is supported and the start address is valid"
        )
