# Quick Module Mapping Reference

## ✅ Already Fixed Test Files
- test_cli_tools_mocked.py (14/14 passing)
- test_json_extraction_performance.py
- test_json_parsing_optimization.py
- test_caching_optimizations.py
- test_command_batching_optimization.py

## 🔧 Test Files Needing Fixes

### test_emulation_tools.py
```python
# Change:
cli_tools._parse_register_state → decompilation._parse_register_state
cli_tools.emulate_machine_code → decompilation.emulate_machine_code
monkeypatch.setattr(cli_tools, "execute_subprocess_async", ...) → 
    monkeypatch.setattr(decompilation, "execute_subprocess_async", ...)
```

### test_performance.py
```python
# Change:
lib_tools._format_lief_output → lief_tools._format_lief_output
lib_tools._IOC_IPV4_PATTERN → ioc_tools._IOC_IPV4_PATTERN
```

### test_performance_improvements.py
```python
# Change:
lib_tools._format_yara_match → yara_tools._format_yara_match
```

## Quick Search Commands

Find where a function moved:
```bash
# Windows PowerShell
Get-ChildItem -Recurse -Filter "*.py" reversecore_mcp/tools/ | Select-String "def function_name"

# Or use grep
grep -r "def function_name" reversecore_mcp/tools/
```

Find failing tests:
```bash
pytest tests/unit --no-cov -q -k "not caching" 2>&1 | grep FAILED
```

## Module Import Template

```python
# Old way (still works for main tools):
from reversecore_mcp.tools import cli_tools
from reversecore_mcp.tools import lib_tools

# New way (for internal/helper functions):
from reversecore_mcp.tools.r2_analysis import _execute_r2_command, trace_execution_path
from reversecore_mcp.tools.decompilation import emulate_machine_code, _parse_register_state
from reversecore_mcp.tools.signature_tools import generate_signature, _sanitize_filename_for_rule
from reversecore_mcp.tools.diff_tools import match_libraries, _extract_library_name
from reversecore_mcp.tools.static_analysis import run_strings, extract_rtti_info
from reversecore_mcp.tools.ioc_tools import extract_iocs, _IOC_IPV4_PATTERN
from reversecore_mcp.tools.yara_tools import run_yara, _format_yara_match
from reversecore_mcp.tools.lief_tools import parse_binary_with_lief, _format_lief_output
```
