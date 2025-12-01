# Reversecore MCP Tools Documentation

This document provides a detailed reference for all available tools in the Reversecore MCP server.

## Plugin: adaptive_vaccine
Automated defense generation tool (YARA rules, binary patching).

### `adaptive_vaccine`

Generate automated defenses against detected threats.

Actions:
- "yara": Generate YARA detection rule
- "patch": Generate binary patch (requires file_path)
- "both": Generate both YARA rule and patch

Args:
    threat_report: Threat information from Ghost Trace or Trinity Defense
                  Format: {
                      "function": "func_name",
                      "address": "0x401000",
                      "instruction": "cmp eax, 0xDEADBEEF",
                      "reason": "Magic value detected",
                      "refined_code": "if (magic_val == 0xDEADBEEF) ..." (optional)
                  }
    action: Type of defense to generate
    file_path: Path to binary (required for "patch" action)
    dry_run: If True, only preview patch without applying

Returns:
    ToolResult containing generated defenses

**Arguments:**

- `threat_report` (dict)
- `action` (str) (default: `yara`)
- `file_path` (str | None) (default: `None`)
- `dry_run` (bool) (default: `True`)

---

## Plugin: decompilation
Decompilation and code recovery tools for binary analysis.

### `emulate_machine_code`

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

**Arguments:**

- `file_path` (str)
- `start_address` (str)
- `instructions` (int) (default: `50`)
- `timeout` (int) (default: `120`)

---

### `get_pseudo_code`

Generate pseudo C code (decompilation) for a function using radare2's pdc command.

This tool decompiles binary code into C-like pseudocode, making it much easier
to understand program logic compared to raw assembly. The output can be further
refined by AI for better readability.

**Use Cases:**
- Quick function understanding without reading assembly
- AI-assisted code analysis and refactoring
- Documentation generation from binaries
- Reverse engineering workflow optimization

**Note:** The output is "pseudo C" - it may not be syntactically perfect C,
but provides a high-level representation of the function logic.

Args:
    file_path: Path to the binary file (must be in workspace)
    address: Function address to decompile (e.g., 'main', '0x401000', 'sym.foo')
    timeout: Execution timeout in seconds (default 300)

Returns:
    ToolResult with pseudo C code string

Example:
    get_pseudo_code("/app/workspace/sample.exe", "main")
    # Returns C-like code representation of the main function

**Arguments:**

- `file_path` (str)
- `address` (str) (default: `main`)
- `timeout` (int) (default: `300`)

---

### `recover_structures`

Recover C++ class structures and data types from binary code.

This is THE game-changer for C++ reverse engineering. Transforms cryptic
"this + 0x4" memory accesses into meaningful "Player.health" structure fields.
Uses Ghidra's powerful data type propagation and structure recovery algorithms.

**Why Structure Recovery Matters:**
- **C++ Analysis**: 99% of game clients and commercial apps are C++
- **Understanding**: "this + 0x4" means nothing, "Player.health = 100" tells a story
- **AI Comprehension**: AI can't understand raw offsets, but understands named fields
- **Scale**: One structure definition can clarify thousands of lines of code

**Performance Tips (for large binaries like game clients):**
- Use `fast_mode=True` (default) to skip full binary analysis
- Use `use_ghidra=False` for quick radare2-based analysis
- For best results on first run, set `fast_mode=False` but expect longer wait

**How It Works:**
1. Analyze memory access patterns in the function
2. Identify structure layouts from offset usage
3. Use data type propagation to infer field types
4. Generate C structure definitions with meaningful names

**Use Cases:**
- Game hacking: Recover Player, Entity, Weapon structures
- Malware analysis: Understand malware configuration structures
- Vulnerability research: Find buffer overflow candidates in structs
- Software auditing: Document undocumented data structures

**Ghidra vs Radare2:**
- Ghidra (default): Superior type recovery, structure propagation, C++ support
- Radare2 (fallback): Basic structure definition, faster but less intelligent

Args:
    file_path: Path to the binary file (must be in workspace)
    function_address: Function to analyze for structure usage (e.g., 'main', '0x401000')
    use_ghidra: Use Ghidra for advanced recovery (default True), or radare2 for basic
    fast_mode: Skip full binary analysis for faster startup (default True)
    timeout: Execution timeout in seconds (default 300 seconds)
    ctx: FastMCP Context (auto-injected)

Returns:
    ToolResult with recovered structures in C format:
    {
        "structures": [
            {
                "name": "Player",
                "size": 64,
                "fields": [
                    {"offset": "0x0", "type": "int", "name": "health"},
                    {"offset": "0x4", "type": "int", "name": "armor"},
                    {"offset": "0x8", "type": "Vector3", "name": "position"}
                ]
            }
        ],
        "c_definitions": "struct Player { int health; int armor; Vector3 position; };"
    }

Example:
    # Fast structure recovery (recommended for large binaries)
    recover_structures("/app/workspace/game.exe", "main")

    # More thorough analysis (slower but more accurate)
    recover_structures("/app/workspace/game.exe", "main", fast_mode=False)

    # Use radare2 for quick analysis
    recover_structures("/app/workspace/binary", "0x401000", use_ghidra=False)

**Arguments:**

- `file_path` (str)
- `function_address` (str)
- `use_ghidra` (bool) (default: `True`)
- `fast_mode` (bool) (default: `True`)
- `timeout` (int) (default: `600`)

---

### `smart_decompile`

Decompile a function to pseudo C code using Ghidra or radare2.

This tool provides decompilation for a specific function in a binary,
making it easier to understand the logic without reading raw assembly.

**Decompiler Selection:**
- Ghidra (default): More accurate, better type recovery, industry-standard
- radare2 (fallback): Faster, lighter weight, good for quick analysis

Args:
    file_path: Path to the binary file (must be in workspace)
    function_address: Function address to decompile (e.g., 'main', '0x401000')
    timeout: Execution timeout in seconds (default 300)
    use_ghidra: Use Ghidra decompiler if available (default True)
    ctx: FastMCP Context (auto-injected)

Returns:
    ToolResult with decompiled pseudo C code

**Arguments:**

- `file_path` (str)
- `function_address` (str)
- `timeout` (int) (default: `120`)
- `use_ghidra` (bool) (default: `True`)

---

## Plugin: diff_tools
Tools for binary diffing, variant analysis, and library matching.

### `analyze_variant_changes`

Analyze structural changes between two binary variants (Lineage Mapper).

This tool combines binary diffing with control flow analysis to understand
*how* a binary has evolved. It identifies the most modified functions and
generates their Control Flow Graphs (CFG) for comparison.

**Use Cases:**
- **Malware Lineage**: "How did Lazarus Group modify their backdoor?"
- **Patch Diffing**: "What logic changed in the vulnerable function?"
- **Variant Analysis**: "Is this a new version of the same malware?"

Args:
    file_path_a: Path to the original binary
    file_path_b: Path to the variant binary
    top_n: Number of top changed functions to analyze in detail (default: 3)
    timeout: Execution timeout in seconds

Returns:
    ToolResult with diff summary and CFG data for top changed functions.

**Arguments:**

- `file_path_a` (str)
- `file_path_b` (str)
- `top_n` (int) (default: `3`)
- `timeout` (int) (default: `120`)

---

### `diff_binaries`

Compare two binary files to identify code changes and modifications.

This tool uses radiff2 to perform binary diffing, which is essential for:
- **Patch Analysis (1-day Exploits)**: Compare pre-patch and post-patch binaries
  to identify security vulnerabilities fixed in updates
- **Game Hacking**: Find offset changes after game updates to maintain functionality
- **Malware Variant Analysis**: Identify code differences between malware variants
  (e.g., "90% similar to Lazarus malware, but C2 address generation changed")

The tool provides:
- Similarity score (0.0-1.0) between binaries
- List of code changes with addresses and descriptions
- Optional function-level comparison for targeted analysis

Args:
    file_path_a: Path to the first binary file (e.g., pre-patch version)
    file_path_b: Path to the second binary file (e.g., post-patch version)
    function_name: Optional function name to compare (e.g., "main", "sym.decrypt").
                  If None, performs whole-binary comparison.
    max_output_size: Maximum output size in bytes (default: 10MB)
    timeout: Timeout in seconds (default: 300s)

Returns:
    ToolResult with structured JSON containing:
    - similarity: Float between 0.0 and 1.0 indicating code similarity
    - changes: List of detected changes with addresses and descriptions
    - function_specific: Boolean indicating if function-level diff was performed

Example:
    # Compare two versions of a patched binary
    diff_binaries("/app/workspace/app_v1.0.exe", "/app/workspace/app_v1.1.exe")

    # Compare specific function between versions
    diff_binaries("/app/workspace/malware_old.exe", "/app/workspace/malware_new.exe", "main")

Output Format:
    {
      "similarity": 0.95,
      "function_specific": false,
      "changes": [
        {
          "address": "0x401050",
          "type": "code_change",
          "description": "Instruction changed from JNZ to JZ"
        },
        {
          "address": "0x401080",
          "type": "new_block",
          "description": "Added security check"
        }
      ],
      "total_changes": 2
    }

**Arguments:**

- `file_path_a` (str)
- `file_path_b` (str)
- `function_name` (str) (default: `None`)
- `max_output_size` (int) (default: `10000000`)
- `timeout` (int) (default: `120`)

---

### `match_libraries`

Match and filter known library functions to focus on user code.

This tool uses radare2's zignatures (FLIRT-compatible signature matching) to:
- **Reduce Analysis Noise**: Skip analysis of known library functions (strcpy, malloc, etc.)
- **Focus on User Code**: Identify which functions are original vs library code
- **Save Time & Tokens**: Reduce analysis scope by 80% by filtering out standard libraries
- **Improve Accuracy**: Focus AI analysis on the actual malicious/interesting code

Common use cases:
- Analyzing large binaries (>25MB) where most code is OpenSSL, zlib, MFC, etc.
- Game client reverse engineering (filter out Unreal Engine / Unity standard library)
- Malware analysis (focus on custom malware code, skip Windows API wrappers)

The tool automatically uses built-in signature databases for common libraries
and can optionally use custom signature databases for specialized analysis.

Args:
    file_path: Path to the binary file to analyze
    signature_db: Optional path to custom signature database file (.sig format).
                 If None, uses radare2's built-in signature databases.
    max_output_size: Maximum output size in bytes (default: 10MB)
    timeout: Timeout in seconds (default: 600s)
    ctx: FastMCP Context (auto-injected)

Returns:
    ToolResult with structured JSON containing:
    - total_functions: Total number of functions found
    - library_functions: Number of matched library functions
    - user_functions: Number of unmatched (user) functions to analyze
    - library_matches: List of matched library functions with details
    - user_function_list: List of user function addresses/names for further analysis
    - noise_reduction_percentage: Percentage of functions filtered out

Example:
    # Auto-detect standard libraries
    match_libraries("/app/workspace/large_app.exe")

    # Use custom signature database
    match_libraries("/app/workspace/game.exe", "/app/rules/game_engine.sig")

Output Format:
    {
      "total_functions": 1250,
      "library_functions": 1000,
      "user_functions": 250,
      "noise_reduction_percentage": 80.0,
      "library_matches": [
        {
          "address": "0x401000",
          "name": "strcpy",
          "library": "msvcrt"
        },
        {
          "address": "0x401050",
          "name": "malloc",
          "library": "msvcrt"
        }
      ],
      "user_function_list": [
        "0x402000",
        "0x402100",
        "sym.custom_decrypt"
      ]
    }

**Arguments:**

- `file_path` (str)
- `signature_db` (str) (default: `None`)
- `max_output_size` (int) (default: `10000000`)
- `timeout` (int) (default: `600`)

---

## Plugin: file_operations
File management tools for workspace operations.

### `copy_to_workspace`

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

**Arguments:**

- `source_path` (str)
- `destination_name` (str) (default: `None`)

---

### `list_workspace`

List all files in the workspace directory.

Returns:
    ToolResult with list of files in workspace

**Arguments:**


---

### `run_file`

Identify file metadata using the ``file`` CLI utility.

**Arguments:**

- `file_path` (str)
- `timeout` (int) (default: `120`)

---

### `scan_workspace`

Batch scan all files in the workspace using multiple tools in parallel.

This tool performs a comprehensive scan of the workspace to identify files,
analyze binaries, and detect threats. It runs 'run_file', 'parse_binary_with_lief',
and 'run_yara' (if rules exist) on all matching files concurrently.

**Workflow:**
1. Identify files matching patterns (default: all files)
2. Run 'file' command on all files
3. Run 'LIEF' analysis on executable files
4. Run 'YARA' scan if rules are available
5. Aggregate results into a single report

Args:
    file_patterns: List of glob patterns to include (e.g., ["*.exe", "*.dll"]).
                  Default is ["*"] (all files).
    timeout: Global timeout for the batch operation in seconds.
    ctx: FastMCP Context for progress reporting (auto-injected)

Returns:
    ToolResult with aggregated scan results for all files.

**Arguments:**

- `file_patterns` (list) (default: `None`)
- `timeout` (int) (default: `600`)

---

## Plugin: ghost_trace
Hybrid reverse engineering tool (Static + Emulation) for detecting hidden malicious behaviors.

### `ghost_trace`

Detect hidden malicious behaviors using "Ghost Trace" (Static + Emulation).

This tool performs a hybrid analysis:
1. **Scan**: Finds "Orphan Functions" (not called by main) and "Suspicious Logic" (magic value checks).
2. **Hypothesize**: (Optional) If `hypothesis` is provided, it sets up emulation conditions.
3. **Emulate**: (Optional) If `focus_function` is provided, it emulates that specific function
   to verify the hypothesis (e.g., "If register eax=0x1234, does it call system()?").

Args:
    file_path: Path to the binary.
    focus_function: (Optional) Name or address of a specific function to emulate.
    hypothesis: (Optional) Dictionary defining emulation parameters:
                {
                    "registers": {"eax": "0x1234", "zf": "1"},
                    "args": ["arg1", "arg2"],
                    "max_steps": 100
                }
    timeout: Execution timeout.

Returns:
    ToolResult containing suspicious candidates or emulation results.

**Arguments:**

- `file_path` (str)
- `focus_function` (str | None) (default: `None`)
- `hypothesis` (dict[str, typing.Any] | None) (default: `None`)
- `timeout` (int) (default: `300`)

---

## Plugin: lib_tools
Library-backed tools for YARA scanning, disassembly, binary parsing, and IOC extraction.

### `disassemble_with_capstone`

Disassemble binary blobs using the Capstone framework.

**Arguments:**

- `file_path` (str)
- `offset` (int) (default: `0`)
- `size` (int) (default: `1024`)
- `arch` (str) (default: `x86`)
- `mode` (str) (default: `64`)

---

### `extract_iocs`

Extract Indicators of Compromise (IOCs) from text using regex.

This tool automatically finds and extracts potential IOCs like IP addresses,
URLs, and email addresses from any text input (e.g., strings output,
decompiled code, logs).

Args:
    text: The text to analyze for IOCs (or path to a file)
    extract_ips: Whether to extract IPv4 addresses (default: True)
    extract_urls: Whether to extract URLs (default: True)
    extract_emails: Whether to extract email addresses (default: True)
    limit: Maximum number of IOCs to return per category (default: 100)

Returns:
    ToolResult with extracted IOCs in structured format

**Arguments:**

- `text` (str)
- `extract_ips` (bool) (default: `True`)
- `extract_urls` (bool) (default: `True`)
- `extract_emails` (bool) (default: `True`)
- `limit` (int) (default: `100`)

---

### `parse_binary_with_lief`

Parse binary metadata using LIEF and return structured results.

**Arguments:**

- `file_path` (str)
- `format` (str) (default: `json`)

---

### `run_yara`

Scan binaries against YARA rules via ``yara-python``.

**Arguments:**

- `file_path` (str)
- `rule_file` (str)
- `timeout` (int) (default: `300`)

---

## Plugin: neural_decompiler
AI-Simulated Code Refinement Tool for transforming raw decompilation into human-like code.

### `neural_decompile`

Decompile a function and refine it into "human-like" code using the Neural Decompiler.

This tool:
1.  Decompiles the function using Ghidra (preferred) or radare2 (fallback).
2.  Refines the code by renaming variables based on API usage (e.g., `socket` -> `sock_fd`).
3.  Infers structures and adds semantic comments.

Args:
    file_path: Path to the binary.
    function_address: Address or name of the function.
    timeout: Execution timeout.
    use_ghidra: Use Ghidra decompiler if available (default True), fallback to radare2.
    ctx: FastMCP Context (auto-injected).

Returns:
    ToolResult containing the refined "Neural" code.

**Arguments:**

- `file_path` (str)
- `function_address` (str)
- `timeout` (int) (default: `300`)
- `use_ghidra` (bool) (default: `True`)

---

## Plugin: r2_analysis
Radare2-based analysis tools for binary analysis, cross-references, and execution tracing.

### `analyze_xrefs`

Analyze cross-references (xrefs) for a specific address using radare2.

Cross-references show the relationships between code blocks - who calls this
function (callers) and what it calls (callees). This is essential for:
- Understanding program flow
- Tracing data dependencies
- Identifying attack surfaces
- Reverse engineering malware C&C

**xref_type Options:**
- **"to"**: Show who references this address (callers/jumps TO here)
- **"from"**: Show what this address references (calls/jumps FROM here)
- **"all"**: Show both directions (complete relationship map)

Args:
    file_path: Path to the binary file (must be in workspace)
    address: Function or address to analyze (e.g., 'main', '0x401000', 'sym.decrypt')
    xref_type: Type of cross-references to show: 'all', 'to', 'from' (default: 'all')
    timeout: Execution timeout in seconds (default: 300)
    ctx: FastMCP Context for progress reporting (auto-injected)

Returns:
    ToolResult with structured JSON containing xrefs data:
    {
        "address": "main",
        "xref_type": "all",
        "xrefs_to": [{"from": "0x401050", "type": "call", "fcn_name": "entry0"}],
        "xrefs_from": [{"addr": "0x401100", "type": "call", "fcn_name": "printf"}],
        "summary": "2 reference(s) TO this address (callers), 1 reference(s) FROM this address (callees)",
        "total_refs_to": 2,
        "total_refs_from": 1
    }

Example:
    # Find who calls the suspicious 'decrypt' function
    analyze_xrefs("/app/workspace/malware.exe", "sym.decrypt", "to")

    # Find what APIs a malware function uses
    analyze_xrefs("/app/workspace/malware.exe", "0x401000", "from")

    # Get complete relationship map
    analyze_xrefs("/app/workspace/malware.exe", "main", "all")

**Arguments:**

- `file_path` (str)
- `address` (str)
- `xref_type` (str) (default: `all`)
- `timeout` (int) (default: `120`)

---

### `generate_function_graph`

Generate a Control Flow Graph (CFG) for a specific function.

This tool uses radare2 to analyze the function structure and returns
a visualization code (Mermaid by default) or PNG image that helps AI understand
the code flow without reading thousands of lines of assembly.

Args:
    file_path: Path to the binary file (must be in workspace)
    function_address: Function address (e.g., 'main', '0x140001000', 'sym.foo')
    format: Output format ('mermaid', 'json', 'dot', or 'png'). Default is 'mermaid'.
    timeout: Execution timeout in seconds

Returns:
    ToolResult with CFG visualization, JSON data, or PNG image

**Arguments:**

- `file_path` (str)
- `function_address` (str)
- `format` (str) (default: `mermaid`)
- `timeout` (int) (default: `120`)

---

### `run_radare2`

Execute vetted radare2 commands for binary triage.

**Arguments:**

- `file_path` (str)
- `r2_command` (str)
- `max_output_size` (int) (default: `10000000`)
- `timeout` (int) (default: `120`)

---

### `trace_execution_path`

Trace function calls backwards from a target function (Sink) to find potential execution paths.

This tool helps identify "Exploit Paths" by finding which functions call a dangerous
target function (like 'system', 'strcpy', 'execve'). It performs a recursive
cross-reference analysis (backtrace) to map out how execution reaches the target.

**Use Cases:**
- **Vulnerability Analysis**: Check if user input (main/recv) reaches 'system'
- **Reachability Analysis**: Verify if a vulnerable function is actually called
- **Taint Analysis Helper**: Provide the path for AI to perform manual taint checking

Args:
    file_path: Path to the binary file
    target_function: Name or address of the target function (e.g., 'sym.imp.system', '0x401000')
    max_depth: Maximum depth of backtrace (default: 3)
    max_paths: Maximum number of paths to return (default: 5)
    timeout: Execution timeout in seconds

Returns:
    ToolResult with a list of execution paths (call chains).

**Arguments:**

- `file_path` (str)
- `target_function` (str)
- `max_depth` (int) (default: `3`)
- `max_paths` (int) (default: `5`)
- `timeout` (int) (default: `120`)

---

## Plugin: signature_tools
Tools for generating YARA rules and binary signatures.

### `generate_signature`

Generate a YARA signature from opcode bytes at a specific address.

This tool extracts opcode bytes from a function or code section and formats
them as a YARA rule, enabling automated malware detection. It attempts to
mask variable values (addresses, offsets) to create more flexible signatures.

**Use Cases:**
- Generate detection signatures for malware samples
- Create YARA rules for threat hunting
- Automate IOC (Indicator of Compromise) generation
- Build malware family signatures

**Workflow:**
1. Extract opcode bytes from specified address
2. Apply basic masking for variable values (optional)
3. Format as YARA rule template
4. Return ready-to-use YARA rule

Args:
    file_path: Path to the binary file (must be in workspace)
    address: Start address for signature extraction (e.g., 'main', '0x401000')
    length: Number of bytes to extract (default 32, recommended 16-64)
    timeout: Execution timeout in seconds (default 300)

Returns:
    ToolResult with YARA rule string

Example:
    generate_signature("/app/workspace/malware.exe", "0x401000", 48)
    # Returns a YARA rule with extracted byte pattern

**Arguments:**

- `file_path` (str)
- `address` (str)
- `length` (int) (default: `32`)
- `timeout` (int) (default: `120`)

---

### `generate_yara_rule`

Generate a YARA rule from function bytes.

This tool extracts bytes from a function and generates a ready-to-use
YARA rule for malware detection and threat hunting.

Args:
    file_path: Path to the binary file (must be in workspace)
    function_address: Function address to extract bytes from (e.g., 'main', '0x401000')
    rule_name: Name for the YARA rule (default 'auto_generated_rule')
    byte_length: Number of bytes to extract (default 64, max 1024)
    timeout: Execution timeout in seconds (default 300)

Returns:
    ToolResult with YARA rule string

**Arguments:**

- `file_path` (str)
- `function_address` (str)
- `rule_name` (str) (default: `auto_generated_rule`)
- `byte_length` (int) (default: `64`)
- `timeout` (int) (default: `300`)

---

## Plugin: static_analysis
Static analysis tools for string extraction, version scanning, and RTTI analysis.

### `extract_rtti_info`

Extract RTTI (Run-Time Type Information) from C++ binaries.

RTTI provides class names and inheritance hierarchies in C++ binaries,
which is invaluable for understanding object-oriented malware and game clients.

Args:
    file_path: Path to the binary file
    timeout: Execution timeout in seconds

Returns:
    ToolResult with extracted class names and type information

**Arguments:**

- `file_path` (str)
- `timeout` (int) (default: `120`)

---

### `run_binwalk`

Analyze binaries for embedded content using binwalk.

**Arguments:**

- `file_path` (str)
- `depth` (int) (default: `8`)
- `max_output_size` (int) (default: `10000000`)
- `timeout` (int) (default: `120`)

---

### `run_binwalk_extract`

Extract embedded files and file systems from a binary using binwalk.

This tool performs deep extraction of embedded content, including:
- Compressed archives (gzip, bzip2, lzma, xz)
- File systems (squashfs, cramfs, jffs2, ubifs)
- Firmware images and bootloaders
- Nested/matryoshka content (files within files)

**Use Cases:**
- **Firmware Analysis**: Extract file systems from router/IoT firmware
- **Malware Unpacking**: Extract payloads from packed/embedded malware
- **Forensics**: Recover embedded files from disk images
- **CTF Challenges**: Extract hidden data from challenge files

Args:
    file_path: Path to the binary file to extract
    output_dir: Directory to extract files to (default: creates temp dir)
    matryoshka: Enable recursive extraction (files within files)
    depth: Maximum extraction depth for nested content (default: 8)
    max_output_size: Maximum output size in bytes
    timeout: Extraction timeout in seconds (default: 600 for large files)

Returns:
    ToolResult with extraction summary including:
    - extracted_files: List of extracted files with paths and types
    - output_directory: Path to extraction output
    - total_size: Total size of extracted content
    - extraction_depth: Maximum depth reached during extraction

Example:
    >>> result = await run_binwalk_extract("/path/to/firmware.bin")
    >>> print(result.data["extracted_files"])
    [{"path": "squashfs-root/etc/passwd", "type": "ASCII text", "size": 1234}, ...]

**Arguments:**

- `file_path` (str)
- `output_dir` (str) (default: `None`)
- `matryoshka` (bool) (default: `True`)
- `depth` (int) (default: `8`)
- `max_output_size` (int) (default: `50000000`)
- `timeout` (int) (default: `600`)

---

### `run_strings`

Extract printable strings using the ``strings`` CLI.

**Arguments:**

- `file_path` (str)
- `min_length` (int) (default: `4`)
- `max_output_size` (int) (default: `10000000`)
- `timeout` (int) (default: `120`)

---

### `scan_for_versions`

Extract library version strings and CVE clues from a binary.

This tool acts as a "Version Detective", scanning the binary for strings that
look like version numbers or library identifiers (e.g., "OpenSSL 1.0.2g",
"GCC 5.4.0"). It helps identify outdated components and potential CVEs.

**Use Cases:**
- **SCA (Software Composition Analysis)**: Identify open source components
- **Vulnerability Scanning**: Find outdated libraries (e.g., Heartbleed-vulnerable OpenSSL)
- **Firmware Analysis**: Determine OS and toolchain versions

Args:
    file_path: Path to the binary file
    timeout: Execution timeout in seconds

Returns:
    ToolResult with detected libraries and versions.

**Arguments:**

- `file_path` (str)
- `timeout` (int) (default: `120`)

---

## Plugin: trinity_defense
Integrated automated defense framework (Ghost Trace, Neural Decompiler, Adaptive Vaccine).

### `trinity_defense`

Trinity Defense System - Full-cycle automated threat detection and neutralization.

This orchestrator runs a 3-phase pipeline:
- Phase 1 (DISCOVER): Ghost Trace finds hidden threats
- Phase 2 (UNDERSTAND): Neural Decompiler analyzes threat intent
- Phase 3 (NEUTRALIZE): Adaptive Vaccine generates defenses

Modes:
- "discover": Phase 1 only (Ghost Trace)
- "analyze": Phase 1+2 (Ghost Trace + Neural Decompiler)
- "full": All 3 phases (+ Adaptive Vaccine)

Args:
    file_path: Path to the binary to analyze
    mode: Analysis mode ("discover", "analyze", or "full")
    max_threats: Maximum number of threats to analyze in detail (default: 5)
    generate_vaccine: Whether to generate YARA rules (default: True)

Returns:
    ToolResult containing comprehensive threat report

**Arguments:**

- `file_path` (str)
- `mode` (str) (default: `full`)
- `max_threats` (int) (default: `5`)
- `generate_vaccine` (bool) (default: `True`)

---
