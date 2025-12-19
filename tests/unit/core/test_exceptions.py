"""
Unit tests for core.exceptions module.
"""

from reversecore_mcp.core.exceptions import (
    BinaryAnalysisError,
    DecompilationError,
    DisassemblyError,
    EmulationError,
    ExecutionTimeoutError,
    GhidraConnectionError,
    OutputLimitExceededError,
    PathTraversalError,
    Radare2Error,
    ReversecoreError,
    SecurityViolationError,
    SignatureGenerationError,
    StructureRecoveryError,
    ToolNotFoundError,
    ToolTimeoutError,
    WorkspaceError,
)


class TestExceptions:
    """Test cases for custom exception classes."""

    def test_tool_not_found_error(self):
        """Test ToolNotFoundError exception."""
        error = ToolNotFoundError("r2")
        assert error.tool_name == "r2"
        assert "r2" in str(error)
        assert "not found" in str(error).lower()

    def test_execution_timeout_error(self):
        """Test ExecutionTimeoutError exception."""
        error = ExecutionTimeoutError(300)
        assert error.timeout_seconds == 300
        assert "300" in str(error)
        assert "timed out" in str(error).lower() or "timeout" in str(error).lower()

    def test_output_limit_exceeded_error(self):
        """Test OutputLimitExceededError exception."""
        error = OutputLimitExceededError(max_size=1000, actual_size=2000)
        assert error.max_size == 1000
        assert error.actual_size == 2000
        assert "1000" in str(error)
        assert "2000" in str(error)
        assert "truncated" in str(error).lower()

    def test_exception_inheritance(self):
        """Test that all exceptions inherit from ReversecoreError."""
        assert issubclass(ToolNotFoundError, ReversecoreError)
        assert issubclass(ExecutionTimeoutError, ReversecoreError)
        assert issubclass(OutputLimitExceededError, ReversecoreError)


class TestBinaryAnalysisExceptions:
    """Test cases for binary analysis exception hierarchy."""

    def test_binary_analysis_error(self):
        """Test base BinaryAnalysisError exception."""
        error = BinaryAnalysisError(
            "Analysis failed",
            binary_path="/path/to/binary",
            tool_name="radare2",
        )
        assert error.binary_path == "/path/to/binary"
        assert error.tool_name == "radare2"
        assert error.error_code == "RCMCP-E100"
        assert "Analysis failed" in str(error)

    def test_decompilation_error(self):
        """Test DecompilationError exception."""
        error = DecompilationError(
            "Function not found",
            function_address="0x401000",
            binary_path="/path/to/binary",
        )
        assert error.function_address == "0x401000"
        assert error.binary_path == "/path/to/binary"
        assert error.tool_name == "ghidra"
        assert error.error_code == "RCMCP-E101"
        assert "0x401000" in str(error)

    def test_disassembly_error(self):
        """Test DisassemblyError exception."""
        error = DisassemblyError(
            "Invalid address",
            address="0x401000",
            binary_path="/path/to/binary",
        )
        assert error.address == "0x401000"
        assert error.error_code == "RCMCP-E102"
        assert "0x401000" in str(error)

    def test_structure_recovery_error(self):
        """Test StructureRecoveryError exception."""
        error = StructureRecoveryError(
            "No structures found",
            function_address="main",
        )
        assert error.function_address == "main"
        assert error.error_code == "RCMCP-E103"

    def test_signature_generation_error(self):
        """Test SignatureGenerationError exception."""
        error = SignatureGenerationError(
            "Not enough bytes",
            address="0x401000",
        )
        assert error.address == "0x401000"
        assert error.error_code == "RCMCP-E104"

    def test_emulation_error(self):
        """Test EmulationError exception."""
        error = EmulationError(
            "Invalid instruction",
            start_address="0x401000",
        )
        assert error.start_address == "0x401000"
        assert error.error_code == "RCMCP-E105"

    def test_binary_analysis_inheritance(self):
        """Test that binary analysis exceptions inherit correctly."""
        assert issubclass(BinaryAnalysisError, ReversecoreError)
        assert issubclass(DecompilationError, BinaryAnalysisError)
        assert issubclass(DisassemblyError, BinaryAnalysisError)
        assert issubclass(StructureRecoveryError, BinaryAnalysisError)
        assert issubclass(SignatureGenerationError, BinaryAnalysisError)
        assert issubclass(EmulationError, BinaryAnalysisError)


class TestToolSpecificExceptions:
    """Test cases for tool-specific exceptions."""

    def test_tool_timeout_error(self):
        """Test ToolTimeoutError exception."""
        error = ToolTimeoutError(
            tool_name="ghidra",
            timeout_seconds=300,
            operation="decompilation",
        )
        assert error.tool_name == "ghidra"
        assert error.timeout_seconds == 300
        assert error.operation == "decompilation"
        assert error.error_code == "RCMCP-E200"
        assert "ghidra" in str(error)
        assert "300" in str(error)
        assert "decompilation" in str(error)

    def test_tool_timeout_error_no_operation(self):
        """Test ToolTimeoutError without operation."""
        error = ToolTimeoutError(tool_name="radare2", timeout_seconds=120)
        assert error.operation is None
        assert "radare2" in str(error)

    def test_ghidra_connection_error(self):
        """Test GhidraConnectionError exception."""
        error = GhidraConnectionError(
            "Connection refused",
            host="localhost",
            port=18489,
        )
        assert error.host == "localhost"
        assert error.port == 18489
        assert error.error_code == "RCMCP-E201"
        assert "localhost" in str(error)
        assert "18489" in str(error)

    def test_radare2_error(self):
        """Test Radare2Error exception."""
        error = Radare2Error(
            "Command failed",
            command="afl",
            binary_path="/path/to/binary",
        )
        assert error.command == "afl"
        assert error.binary_path == "/path/to/binary"
        assert error.error_code == "RCMCP-E202"
        assert "afl" in str(error)


class TestSecurityExceptions:
    """Test cases for security-related exceptions."""

    def test_workspace_error(self):
        """Test WorkspaceError exception."""
        error = WorkspaceError(
            "File not in workspace",
            path="/etc/passwd",
        )
        assert error.path == "/etc/passwd"
        assert error.error_code == "RCMCP-E300"

    def test_security_violation_error(self):
        """Test SecurityViolationError exception."""
        error = SecurityViolationError(
            "Access denied",
            attempted_path="/etc/shadow",
        )
        assert error.attempted_path == "/etc/shadow"
        assert error.error_code == "RCMCP-E301"

    def test_path_traversal_error(self):
        """Test PathTraversalError exception."""
        error = PathTraversalError("../../../etc/passwd")
        assert error.attempted_path == "../../../etc/passwd"
        assert error.error_code == "RCMCP-E302"
        assert "traversal" in str(error).lower()

    def test_security_inheritance(self):
        """Test security exception inheritance."""
        assert issubclass(SecurityViolationError, ReversecoreError)
        assert issubclass(PathTraversalError, SecurityViolationError)
        assert issubclass(WorkspaceError, ReversecoreError)
