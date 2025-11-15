"""
More unit tests for tools.cli_tools covering additional branches.
"""

import pytest

from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.tools import cli_tools


def test_run_radare2_invalid_command_sanitization(monkeypatch, tmp_path):
    path = tmp_path / "a.out"
    path.write_text("bin")
    monkeypatch.setattr(
        cli_tools, "validate_file_path", lambda p, read_only=False: path
    )

    def _validate(cmd):
        raise ValidationError("invalid command")

    monkeypatch.setattr(cli_tools, "validate_r2_command", _validate)
    out = cli_tools.run_radare2(str(path), "bad")
    assert out.status == "error" and out.error_code == "VALIDATION_ERROR"


def test_run_strings_validation_error(monkeypatch, tmp_path):
    def _raise(_p, read_only=False):
        raise ValidationError("Outside workspace")

    monkeypatch.setattr(cli_tools, "validate_file_path", _raise)
    out = cli_tools.run_strings(str(tmp_path / "x"))
    assert out.status == "error" and out.error_code == "VALIDATION_ERROR"
