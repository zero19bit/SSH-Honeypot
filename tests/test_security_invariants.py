"""Regression guards for the project's most important security property."""

import ast
from pathlib import Path


PACKAGE = Path(__file__).parents[1] / "honeypot"


def test_no_process_execution_or_host_file_api_in_runtime() -> None:
    banned_import_roots = {"subprocess", "requests", "urllib", "httpx", "aiohttp"}
    banned_direct_calls = {"open", "exec", "eval", "compile", "__import__"}
    banned_attribute_calls = {
        "system",
        "popen",
        "spawnl",
        "spawnlp",
        "spawnv",
        "spawnvp",
        "Popen",
        "check_call",
        "check_output",
    }
    violations: list[str] = []
    for source_path in sorted(PACKAGE.rglob("*.py")):
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".", 1)[0] in banned_import_roots:
                        violations.append(f"{source_path.name}: import {alias.name}")
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module.split(".", 1)[0] in banned_import_roots:
                    violations.append(f"{source_path.name}: from {node.module}")
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in banned_direct_calls:
                    violations.append(f"{source_path.name}: call {node.func.id}")
                if isinstance(node.func, ast.Attribute) and node.func.attr in banned_attribute_calls:
                    violations.append(f"{source_path.name}: call .{node.func.attr}")
    assert violations == []


def test_simulation_layer_has_no_network_module() -> None:
    for filename in ("commands.py", "filesystem.py", "fake_data.py"):
        tree = ast.parse((PACKAGE / filename).read_text(encoding="utf-8"))
        imported = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        assert "socket" not in imported
        assert "paramiko" not in imported


def test_no_real_shell_tokens_in_runtime_source() -> None:
    forbidden = ("subprocess.", "os.system(", "os.popen(", "shell=True")
    for source_path in sorted(PACKAGE.rglob("*.py")):
        source = source_path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in source, f"{token!r} found in {source_path.name}"
