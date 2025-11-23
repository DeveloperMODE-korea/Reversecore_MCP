# Test Fixing Guide for GitHub Copilot

## Context
After refactoring `cli_tools.py` and `lib_tools.py` into smaller modules, approximately **50 tests are failing** due to incorrect import/monkeypatch paths.

## Current Status
- ✅ **449 tests passing**
- ❌ **50 tests failing**
- ❌ **13 errors**

## Module Mapping (After Refactoring)

### From `cli_tools.py` → Multiple modules:
```
emulate_machine_code          → decompilation.py
_parse_register_state         → decompilation.py
trace_execution_path          → r2_analysis.py
_execute_r2_command           → r2_analysis.py
_build_r2_cmd                 → r2_analysis.py
_calculate_dynamic_timeout    → r2_analysis.py
_get_r2_project_name          → r2_analysis.py
_extract_first_json           → r2_analysis.py
_parse_json_output            → r2_analysis.py
generate_signature            → signature_tools.py
generate_yara_rule            → signature_tools.py
_sanitize_filename_for_rule   → signature_tools.py
match_libraries               → diff_tools.py
diff_binaries                 → diff_tools.py
_extract_library_name         → diff_tools.py
analyze_xrefs                 → r2_analysis.py
recover_structures            → decompilation.py
extract_rtti_info             → static_analysis.py
run_strings                   → static_analysis.py
execute_subprocess_async      → core.execution
```

### From `lib_tools.py` → Multiple modules:
```
extract_iocs              → ioc_tools.py
_IOC_IPV4_PATTERN         → ioc_tools.py
run_yara                  → yara_tools.py
_format_yara_match        → yara_tools.py
disassemble_with_capstone → capstone_tools.py
parse_binary_with_lief    → lief_tools.py
_format_lief_output       → lief_tools.py
```

## Common Fixing Patterns

### Pattern 1: Direct Import Fix
**Before:**
```python
from reversecore_mcp.tools.cli_tools import emulate_machine_code
```

**After:**
```python
from reversecore_mcp.tools.decompilation import emulate_machine_code
```

### Pattern 2: Monkeypatch Path Fix
**Before:**
```python
monkeypatch.setattr(cli_tools, "execute_subprocess_async", mock_func)
```

**After:**
```python
# Find where the function being tested actually imports execute_subprocess_async
# For emulate_machine_code (in decompilation.py):
from reversecore_mcp.tools import decompilation
monkeypatch.setattr(decompilation, "execute_subprocess_async", mock_func)
```

### Pattern 3: unittest.mock.patch Path Fix
**Before:**
```python
with patch('reversecore_mcp.tools.cli_tools.execute_subprocess_async'):
```

**After:**
```python
# For functions in r2_analysis.py:
with patch('reversecore_mcp.tools.r2_analysis.execute_subprocess_async'):

# For functions in decompilation.py:
with patch('reversecore_mcp.tools.decompilation.execute_subprocess_async'):
```

## Step-by-Step Fixing Process

### Step 1: Identify the failing test
```bash
pytest tests/unit/test_emulation_tools.py::test_emulate_machine_code_hex_address --no-cov -v
```

### Step 2: Check the error message
Look for:
- `AttributeError: module 'reversecore_mcp.tools.cli_tools' has no attribute 'xxx'`
- `ImportError: cannot import name 'xxx' from 'reversecore_mcp.tools.cli_tools'`

### Step 3: Find the new location
Use grep to find where the function/class/constant moved:
```bash
grep -r "def function_name" reversecore_mcp/tools/
```

### Step 4: Update the test
Update both:
1. Import statements
2. Monkeypatch/patch paths

### Step 5: Verify
```bash
pytest tests/unit/test_file.py --no-cov -v
```

## Quick Reference: Tests to Fix

Run this to see all failing tests:
```bash
pytest tests/unit --no-cov -q -k "not caching" 2>&1 | grep FAILED
```

## Common Failing Test Files
Based on current run, these files likely need fixes:
- `test_emulation_tools.py` - Uses `emulate_machine_code`, `_parse_register_state` (→ decompilation.py)
- `test_performance.py` - Uses various lib_tools functions
- `test_performance_improvements.py` - Uses `_format_yara_match` (→ yara_tools.py)
- Any test that patches `cli_tools.execute_subprocess_async`

## Important Notes

1. **Facade Pattern**: `cli_tools.py` and `lib_tools.py` still exist as facades that re-export the main tools. Only internal/helper functions need path updates.

2. **execute_subprocess_async**: This is from `reversecore_mcp.core.execution`, but when patching, you need to patch it where it's **imported**, not where it's defined.

3. **Backward Compatibility**: Some internal symbols have been re-exported in the facade for backward compatibility (see `lib_tools.py` `__all__`).

## Example Complete Fix

**File: `tests/unit/test_emulation_tools.py`**

Before:
```python
from reversecore_mcp.tools import cli_tools

def test_parse_register_state_basic():
    result = cli_tools._parse_register_state(ar_output)
    # ...

@pytest.mark.asyncio
async def test_emulate_machine_code_hex_address(monkeypatch, workspace_dir, patched_workspace_config):
    # ...
    monkeypatch.setattr(cli_tools, "execute_subprocess_async", mock_exec)
    result = await cli_tools.emulate_machine_code(...)
```

After:
```python
from reversecore_mcp.tools import cli_tools  # Still OK for main tool functions
from reversecore_mcp.tools import decompilation  # Add for internal functions

def test_parse_register_state_basic():
    result = decompilation._parse_register_state(ar_output)  # Changed
    # ...

@pytest.mark.asyncio
async def test_emulate_machine_code_hex_address(monkeypatch, workspace_dir, patched_workspace_config):
    # ...
    monkeypatch.setattr(decompilation, "execute_subprocess_async", mock_exec)  # Changed
    result = await cli_tools.emulate_machine_code(...)  # Can stay or change to decompilation.emulate_machine_code
```

## Validation

After fixing all tests:
```bash
# Should see significant improvement
pytest tests/unit --no-cov -q

# Target: All tests passing
```

## Questions?
- Check the actual refactored module files in `reversecore_mcp/tools/`
- Look at `test_cli_tools_mocked.py` - it's already been fixed as a reference
