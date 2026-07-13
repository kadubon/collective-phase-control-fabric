# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

from collective_phase_control_fabric.process import run_process


def test_stdin_limit_and_path_boundary(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="stdin exceeds"):
        run_process(
            [sys.executable, "--version"], tmp_path, tmp_path, stdin_bytes=b"xx", stdin_limit=1
        )
    child = tmp_path / "child"
    child.mkdir()
    receipt = run_process([sys.executable, "--version"], child, tmp_path)
    assert receipt["shell"] is False
    assert receipt["stdin_byte_limit"] == 1_048_576
    assert receipt["network_sandboxed"] is False
    with pytest.raises(ValueError, match="outside"):
        run_process([sys.executable, "--version"], tmp_path, tmp_path / "other")


def test_invalid_argv_missing_executable_timeout_and_non_utf8(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="argv"):
        run_process([], tmp_path, tmp_path)
    with pytest.raises(FileNotFoundError):
        run_process(["cpcf-certainly-missing-executable"], tmp_path, tmp_path)
    non_utf8 = run_process(
        [
            sys.executable,
            "-c",
            "import os; os.write(1,b'\\xff'); os.write(2,b'\\xfe')",
        ],
        tmp_path,
        tmp_path,
    )
    assert non_utf8["stdout_utf8_valid"] is False
    assert non_utf8["stderr_utf8_valid"] is False
    receipt = run_process(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        tmp_path,
        tmp_path,
        timeout_seconds=0.05,
    )
    assert receipt["timed_out"] is True
    assert receipt["process_group_cleanup"] in {"complete", "best_effort"}


def test_executable_digest_unknown_for_non_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(shutil, "which", lambda _: str(tmp_path))
    with pytest.raises(OSError):
        run_process(["directory-as-executable"], tmp_path, tmp_path)
