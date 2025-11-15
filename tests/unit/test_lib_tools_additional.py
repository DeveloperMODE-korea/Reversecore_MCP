"""Additional unit tests for tools.lib_tools with mocks."""

import sys
import types

import pytest

from reversecore_mcp.tools import lib_tools


class _Inst:
    def __init__(self, offset, data: bytes):
        self.offset = offset
        self.matched_data = data


class _SM:
    def __init__(self, identifier, instances):
        self.identifier = identifier
        self.instances = instances


class _Match:
    def __init__(self, rule, namespace, tags, meta, strings):
        self.rule = rule
        self.namespace = namespace
        self.tags = tags
        self.meta = meta
        self.strings = strings


def _create_workspace_binary(workspace_dir, name: str, data: bytes = b"abc"):
    path = workspace_dir / name
    path.write_bytes(data)
    return path


def test_run_yara_formatter(
    monkeypatch,
    workspace_dir,
    read_only_dir,
    patched_workspace_config,
):
    test_file = _create_workspace_binary(workspace_dir, "t.bin")
    rule_file = read_only_dir / "rules.yar"
    rule_file.write_text("rule t { condition: true }")

    # Fake yara module injected into sys.modules
    fake_yara = types.ModuleType("yara")

    class _Rules:
        def match(self, f, timeout=300):
            inst1 = _Inst(10, b"abc")
            sm = _SM("$a", [inst1])
            return [_Match("r1", "default", ["tag"], {"k": "v"}, [sm])]

    class _Error(Exception):
        pass

    class _TimeoutError(Exception):
        pass

    def _compile(filepath=None, **_kwargs):
        return _Rules()

    fake_yara.compile = _compile
    fake_yara.Error = _Error
    fake_yara.TimeoutError = _TimeoutError

    monkeypatch.setitem(sys.modules, "yara", fake_yara)

    out = lib_tools.run_yara(str(test_file), str(rule_file))
    assert out.status == "success"
    data = out.data
    assert isinstance(data, dict)
    assert "matches" in data
    assert isinstance(data["matches"], list)
    assert data["matches"][0]["rule"] == "r1"
    assert data["matches"][0]["strings"][0]["identifier"] == "$a"
    assert data["matches"][0]["strings"][0]["offset"] == 10
    assert data["match_count"] == 1


def test_disassemble_invalid_arch_mode(
    workspace_dir,
    patched_workspace_config,
):
    test_file = _create_workspace_binary(workspace_dir, "t.bin", b"\x90\x90\x90\x90")

    # Invalid arch
    out1 = lib_tools.disassemble_with_capstone(str(test_file), arch="badarch", mode="64")
    assert out1.status == "error"
    assert out1.error_code == "INVALID_PARAMETER"
    assert "unsupported architecture" in out1.message.lower()

    # Valid arch but invalid mode
    out2 = lib_tools.disassemble_with_capstone(str(test_file), arch="x86", mode="badmode")
    assert out2.status == "error"
    assert out2.error_code == "INVALID_PARAMETER"
    assert "unsupported mode" in out2.message.lower()


def test_parse_binary_with_lief_error(
    monkeypatch,
    workspace_dir,
    patched_workspace_config,
    patched_config,
):
    test_file = _create_workspace_binary(workspace_dir, "t.bin", b"\x00\x01")

    fake_lief = types.ModuleType("lief")

    class _BadFile(Exception):
        pass

    fake_lief.bad_file = _BadFile
    fake_lief.exception = _BadFile

    def _parse(path):
        raise _BadFile("corrupt binary")

    fake_lief.parse = _parse
    monkeypatch.setitem(sys.modules, "lief", fake_lief)

    out = lib_tools.parse_binary_with_lief(str(test_file))
    assert out.status == "error"
    assert out.error_code == "LIEF_ERROR"
    assert "corrupt" in out.message.lower()
