"""Additional unit tests for tools.cli_tools using mocks."""

import subprocess

from reversecore_mcp.core.exceptions import ExecutionTimeoutError, ToolNotFoundError
from reversecore_mcp.tools import cli_tools


def _create_workspace_file(workspace_dir, name: str, data: str | bytes = "stub"):
    path = workspace_dir / name
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data)
    return path


def test_run_file_success(monkeypatch, workspace_dir, patched_workspace_config):
    mocked_path = _create_workspace_file(workspace_dir, "x")
    monkeypatch.setattr(
        cli_tools,
        "execute_subprocess_streaming",
        lambda cmd, **kw: ("ELF 64-bit", 20),
    )
    out = cli_tools.run_file(str(mocked_path))
    assert out.status == "success" and "ELF" in out.data


def test_run_file_tool_not_found(monkeypatch, workspace_dir, patched_workspace_config):
    mocked_path = _create_workspace_file(workspace_dir, "x")

    def raise_not_found(cmd, **kw):
        raise ToolNotFoundError("file")

    monkeypatch.setattr(cli_tools, "execute_subprocess_streaming", raise_not_found)
    out = cli_tools.run_file(str(mocked_path))
    assert out.status == "error" and out.error_code == "TOOL_NOT_FOUND"


def test_run_strings_timeout(monkeypatch, workspace_dir, patched_workspace_config):
    mocked_path = _create_workspace_file(workspace_dir, "x")

    def raise_timeout(cmd, **kw):
        raise ExecutionTimeoutError(1)

    monkeypatch.setattr(cli_tools, "execute_subprocess_streaming", raise_timeout)
    out = cli_tools.run_strings(str(mocked_path))
    assert out.status == "error" and out.error_code == "TIMEOUT"


def test_run_strings_called_process_error(
    monkeypatch,
    workspace_dir,
    patched_workspace_config,
):
    mocked_path = _create_workspace_file(workspace_dir, "x")

    def raise_cpe(cmd, **kw):
        raise subprocess.CalledProcessError(1, cmd, output="", stderr="bad")

    monkeypatch.setattr(cli_tools, "execute_subprocess_streaming", raise_cpe)
    out = cli_tools.run_strings(str(mocked_path))
    assert out.status == "error" and out.error_code == "INTERNAL_ERROR"


def test_run_binwalk_success(monkeypatch, workspace_dir, patched_workspace_config):
    mocked_path = _create_workspace_file(workspace_dir, "fw.bin")
    monkeypatch.setattr(
        cli_tools,
        "execute_subprocess_streaming",
        lambda cmd, **kw: ("BINWALK OK", 50),
    )
    out = cli_tools.run_binwalk(str(mocked_path))
    assert out.status == "success" and "BINWALK" in out.data


def test_run_binwalk_called_process_error(
    monkeypatch,
    workspace_dir,
    patched_workspace_config,
):
    mocked_path = _create_workspace_file(workspace_dir, "fw.bin")

    def raise_cpe(cmd, **kw):
        raise subprocess.CalledProcessError(2, cmd, output="", stderr="bad arg")

    monkeypatch.setattr(cli_tools, "execute_subprocess_streaming", raise_cpe)
    out = cli_tools.run_binwalk(str(mocked_path))
    assert out.status == "error" and out.error_code == "INTERNAL_ERROR"


def test_run_radare2_success(monkeypatch, workspace_dir, patched_workspace_config):
    mocked_path = _create_workspace_file(workspace_dir, "a.out")
    monkeypatch.setattr(cli_tools, "validate_r2_command", lambda s: s)
    monkeypatch.setattr(
        cli_tools,
        "execute_subprocess_streaming",
        lambda cmd, **kw: ("r2 out", 10),
    )
    out = cli_tools.run_radare2(str(mocked_path), "i")
    assert out.status == "success" and out.data == "r2 out"


def test_run_radare2_tool_not_found(
    monkeypatch,
    workspace_dir,
    patched_workspace_config,
):
    mocked_path = _create_workspace_file(workspace_dir, "a.out")
    monkeypatch.setattr(cli_tools, "validate_r2_command", lambda s: s)

    def raise_not_found(cmd, **kw):
        raise ToolNotFoundError("r2")

    monkeypatch.setattr(cli_tools, "execute_subprocess_streaming", raise_not_found)
    out = cli_tools.run_radare2(str(mocked_path), "i")
    assert out.status == "error" and out.error_code == "TOOL_NOT_FOUND"
