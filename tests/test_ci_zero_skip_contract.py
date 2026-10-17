"""Run a real nested Pytest process to prove skip-fail is enforced."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    "body,expected_rc",
    [
        ("def test_real():\n    assert True\n", 0),
        ("import pytest\ndef test_skipped():\n    pytest.skip('missing backend')\n", 1),
    ],
)
def test_zero_skip_gate_is_executable(
    tmp_path: Path, body: str, expected_rc: int
) -> None:
    root = Path(__file__).resolve().parents[1]
    (tmp_path / "conftest.py").write_text((root / "conftest.py").read_text())
    (tmp_path / "test_check.py").write_text(body)
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-rs", str(tmp_path)],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        check=False,
        timeout=30,
    )
    assert completed.returncode == expected_rc, completed.stdout + completed.stderr
    if expected_rc:
        assert "QUALITY GATE FAILED" in completed.stdout


def test_ci_runs_active_development_branch_and_branch_coverage() -> None:
    ci = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"
    text = ci.read_text()
    assert "branches: [main, dev/strict-telemetry-hardening-20261017]" in text
    assert "--cov-branch" in text
    assert "  workflow_dispatch:" in text
