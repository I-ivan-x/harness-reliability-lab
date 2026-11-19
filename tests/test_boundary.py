"""Check real installed-package boundaries without adding repository paths."""

import ast
import json
import subprocess
import sys
from pathlib import Path

import harness_lab
from harness_lab.cli import doctor_report

FORBIDDEN_ROOTS = {"app", "scripts", "evals"}


def test_runtime_has_no_cross_layer_imports() -> None:
    runtime = Path(harness_lab.__file__).resolve().parent
    violations = []
    for source in runtime.rglob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots = {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                roots = {(node.module or "").split(".")[0]}
            else:
                continue
            if roots & FORBIDDEN_ROOTS:
                violations.append(f"{source.name}:{node.lineno}")
    assert not violations, violations


def test_import_does_not_load_legacy_or_evaluation_modules() -> None:
    report = doctor_report()
    assert report["loaded_forbidden_modules"] == []
    assert report["loaded_module_boundary_ok"] is True


def test_installed_cli_runs_outside_repository(tmp_path: Path) -> None:
    # -I ignores cwd/PYTHONPATH; only the installed package may satisfy the import.
    result = subprocess.run(
        [sys.executable, "-I", "-m", "harness_lab", "doctor"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["loaded_forbidden_modules"] == []
    assert report["loaded_module_boundary_ok"] is True
    assert report["g1_implemented"] is True
    assert Path(report["package_location"]).is_dir()
