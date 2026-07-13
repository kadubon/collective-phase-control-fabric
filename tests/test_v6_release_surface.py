# SPDX-License-Identifier: Apache-2.0
"""Release-surface, offline-first, and publication-safety regressions."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
from cpcf_cli.main import main

ROOT = Path(__file__).resolve().parents[1]


def test_root_distribution_is_single_and_complete() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["project"]["name"] == "collective-phase-control-fabric"
    assert "workspace" not in project["tool"]["uv"]
    assert not any(item.startswith("cpcf-") for item in project["project"]["dependencies"])
    packages = project["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"]
    assert {Path(item).name for item in packages} == {
        "collective_phase_control_fabric",
        "cpcf_api",
        "cpcf_cli",
        "cpcf_runner_protocol",
        "cpcf_worker",
    }
    assert not list((ROOT / "packages").glob("*/pyproject.toml"))


def test_offline_cli_orientation_and_schema_registry(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["agent", "explain", "--json"]) == 0
    explained = json.loads(capsys.readouterr().out)
    assert explained["code"] == "offline_orientation"
    assert explained["claims"]["native_result"] == "operational_organization_profile"
    assert main(["self-check", "--json"]) == 0
    checked = json.loads(capsys.readouterr().out)
    assert checked["code"] == "offline_self_check_passed"
    assert checked["claims"]["schema_count"] > 30
    assert main(["schema", "show", "phase-contract", "--json"]) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown["claims"]["schema"]["$schema"].endswith("2020-12/schema")
    assert main(["schema", "show", "not-a-kind", "--json"]) == 1
    missing = json.loads(capsys.readouterr().out)
    assert missing["code"] == "unknown_document_kind"


def test_self_check_treats_missing_optional_namespace_as_absent(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    original = importlib.util.find_spec

    def find_spec(name: str) -> object:
        if name == "google.cloud.kms":
            raise ModuleNotFoundError("optional namespace is absent")
        return original(name)

    monkeypatch.setattr(importlib.util, "find_spec", find_spec)
    assert main(["self-check", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["claims"]["optional_extras"]["gcp_kms"] is False


def test_publication_hygiene_rejects_sensitive_and_local_content(tmp_path: Path) -> None:
    (tmp_path / "publication-files.txt").write_text("allowed.txt\n", encoding="utf-8")
    local_path = "C:" + "\\Users\\local-user\\private\\record.json"
    (tmp_path / "allowed.txt").write_text(local_path, encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "check_publication_hygiene.py"),
            "--root",
            str(tmp_path),
            "--source-tree",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "windows_home_path" in result.stdout
    assert "local-user" not in result.stdout


def test_release_workflow_is_fail_closed() -> None:
    workflow = (ROOT / ".github" / "workflows" / "workflow.yml").read_text(encoding="utf-8")
    assert "workflow_dispatch:" in workflow
    assert "github.event_name == 'release'" in workflow
    assert "github.event.release.prerelease == false" in workflow
    assert "vars.PYPI_PUBLISH_ENABLED == 'true'" in workflow
    assert "name: pypi" in workflow
    assert "id-token: write" in workflow
    assert "pypa/gh-action-pypi-publish@" in workflow
    assert "packages-dir: dist/" in workflow
    assert "--cov-fail-under=95" in workflow
    assert "check_mutation_score.py mutation-results.txt --minimum 85" in workflow


def test_mutation_score_gate_counts_failures_without_disclosing_mutants(tmp_path: Path) -> None:
    results = tmp_path / "results.txt"
    results.write_text(
        "module.function__mutmut_1: killed\nmodule.function__mutmut_2: survived\n",
        encoding="utf-8",
    )
    failed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "check_mutation_score.py"),
            str(results),
            "--minimum",
            "85",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert failed.returncode == 1
    assert "50.00%" in failed.stdout
    assert "module.function" not in failed.stdout
