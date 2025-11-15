"""
More unit tests for tools.cli_tools covering additional branches.
"""

from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.tools import cli_tools


def test_run_radare2_invalid_command_sanitization(
    monkeypatch,
    workspace_dir,
    patched_workspace_config,
):
    path = workspace_dir / "a.out"
    path.write_text("bin")

    def _validate(cmd):
        raise ValidationError("invalid command")

    monkeypatch.setattr(cli_tools, "validate_r2_command", _validate)
    out = cli_tools.run_radare2(str(path), "bad")
    assert out.status == "error" and out.error_code == "VALIDATION_ERROR"


def test_run_strings_validation_error(
    tmp_path,
    workspace_dir,
    patched_workspace_config,
):
    outside_file = tmp_path / "outside.bin"
    outside_file.write_text("nope")

    out = cli_tools.run_strings(str(outside_file))
    assert out.status == "error" and out.error_code == "VALIDATION_ERROR"
