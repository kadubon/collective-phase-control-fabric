# SPDX-License-Identifier: Apache-2.0
"""A partial, overlapping or altered shard set must never produce a passing score."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from scripts.check_mutation_score import COUNTED_FAILURES, COUNTED_SUCCESSES
from scripts.merge_mutation_results import SHARDS, merge_results, read_results

ROOT = Path(__file__).resolve().parents[1]


def reports(directory: Path) -> dict[str, str]:
    expected = {
        f"example.function__mutmut_{index}": "survived" if index == 1 else "killed"
        for index in range(1, 21)
    }
    for shard in range(SHARDS):
        folder = directory / f"mutation-shard-{shard}"
        folder.mkdir(parents=True)
        (folder / "mutation-results.txt").write_text(
            "".join(
                f"{name}: "
                f"{status if int(name.rsplit('_', 1)[1]) % SHARDS == shard else 'not checked'}\n"
                for name, status in expected.items()
            ),
            encoding="utf-8",
        )
    (directory.parent / "catalogue.json").write_text(
        json.dumps(
            {
                "mutmut_version": "3.6.0",
                "mutant_count": len(expected),
                "sorted_names_sha256": hashlib.sha256(
                    "".join(name + "\n" for name in sorted(expected)).encode()
                ).hexdigest(),
            }
        )
    )
    return expected


def test_complete_shards_reproduce_the_unsharded_score(tmp_path: Path) -> None:
    directory = tmp_path / "shards"
    expected = reports(directory)
    output = tmp_path / "combined.txt"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.merge_mutation_results",
            str(directory),
            str(output),
            "--catalogue",
            str(tmp_path / "catalogue.json"),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "20 unique mutants" in result.stdout and "example.function" not in result.stdout
    assert read_results(output) == merge_results(directory, tmp_path / "catalogue.json") == expected
    for threshold, exit_code in ((85, 0), (96, 1)):
        scored = subprocess.run(
            [
                sys.executable,
                "scripts/check_mutation_score.py",
                str(output),
                "--minimum",
                str(threshold),
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        assert scored.returncode == exit_code and "95.00%" in scored.stdout


@pytest.mark.parametrize("status", sorted(COUNTED_FAILURES | COUNTED_SUCCESSES))
def test_every_terminal_status_is_preserved_without_reclassification(
    tmp_path: Path, status: str
) -> None:
    directory = tmp_path / "shards"
    expected = reports(directory)
    name = "example.function__mutmut_1"
    path = directory / "mutation-shard-1/mutation-results.txt"
    path.write_text(path.read_text().replace(f"{name}: survived", f"{name}: {status}"))
    expected[name] = status
    assert merge_results(directory, tmp_path / "catalogue.json") == expected


@pytest.mark.parametrize(
    ("alteration", "code"),
    [
        ("missing_shard", "mutation_shard_set_mismatch"),
        ("extra_shard", "mutation_shard_set_mismatch"),
        ("missing_report", "mutation_shard_report_missing"),
        ("extra_file", "mutation_shard_files_unexpected"),
        ("catalogue", "mutation_catalogue_mismatch"),
        ("duplicate", "mutation_result_duplicate"),
        ("unknown", "mutation_result_status_unknown"),
        ("malformed", "mutation_result_malformed"),
        ("empty", "mutation_catalogue_empty"),
        ("incomplete", "mutation_shard_incomplete"),
        ("interrupted", "mutation_shard_incomplete"),
        ("overlap", "mutation_shard_overlap"),
        ("all_missing", "mutation_declared_catalogue_mismatch"),
        ("all_renamed", "mutation_declared_catalogue_mismatch"),
        ("wrong_version", "mutation_tool_version_mismatch"),
        ("bad_declaration", "mutation_catalogue_declaration_invalid"),
    ],
)
def test_incomplete_or_corrupt_shards_fail_closed(
    tmp_path: Path, alteration: str, code: str
) -> None:
    directory = tmp_path / "shards"
    reports(directory)
    path = directory / "mutation-shard-1/mutation-results.txt"
    content = path.read_text()
    if alteration == "missing_shard":
        path.unlink()
        path.parent.rmdir()
    elif alteration == "extra_shard":
        (directory / "mutation-shard-5").mkdir()
    elif alteration == "missing_report":
        path.unlink()
    elif alteration == "extra_file":
        (path.parent / "unexpected.txt").write_text("unexpected")
    elif alteration == "catalogue":
        path.write_text("\n".join(content.splitlines()[1:]))
    elif alteration == "duplicate":
        path.write_text(content + content.splitlines()[0] + "\n")
    elif alteration == "unknown":
        path.write_text(content.replace("survived", "successful"))
    elif alteration == "malformed":
        path.write_text(content.replace("__mutmut_1:", "__mutmut_invalid:"))
    elif alteration == "empty":
        path.write_text("")
    elif alteration in {"incomplete", "interrupted"}:
        status = "not checked" if alteration == "incomplete" else "check was interrupted by user"
        path.write_text(content.replace("survived", status))
    elif alteration in {"all_missing", "all_renamed"}:
        for report in directory.glob("*/mutation-results.txt"):
            original = report.read_text()
            updated = (
                "\n".join(original.splitlines()[1:])
                if alteration == "all_missing"
                else original.replace("example.function", "example.other")
            )
            report.write_text(updated)
    elif alteration in {"wrong_version", "bad_declaration"}:
        declaration = tmp_path / "catalogue.json"
        data = json.loads(declaration.read_text())
        if alteration == "wrong_version":
            data["mutmut_version"] = "0.0.0"
        else:
            data["extra"] = True
        declaration.write_text(json.dumps(data))
    else:
        path.write_text(
            content.replace(
                "example.function__mutmut_2: not checked", "example.function__mutmut_2: killed"
            )
        )
    with pytest.raises(ValueError, match=code):
        merge_results(directory, tmp_path / "catalogue.json")
    output = tmp_path / "result.txt"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.merge_mutation_results",
            str(directory),
            str(output),
            "--catalogue",
            str(tmp_path / "catalogue.json"),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1 and code in result.stdout
    assert not output.exists() and "example.function" not in result.stdout


def test_ci_and_release_select_every_mutant_once_and_gate_failed_shards() -> None:
    for name in ("ci.yml", "workflow.yml"):
        jobs = yaml.safe_load((ROOT / ".github/workflows" / name).read_text())["jobs"]
        shard_job = jobs["mutation-shards"]
        matrix = shard_job["strategy"]["matrix"]["include"]
        assert shard_job["strategy"]["fail-fast"] is False
        assert {item["shard"] for item in matrix} == set(range(SHARDS))
        for number in range(1, 1001):
            mutant = f"example.function__mutmut_{number}"
            owners = [
                item["shard"] for item in matrix if fnmatch.fnmatchcase(mutant, item["selector"])
            ]
            assert owners == [number % SHARDS]
        run = next(
            step for step in shard_job["steps"] if step.get("name") == "Run assigned mutants"
        )
        assert 'mutmut run "$MUTATION_SELECTOR"' in run["run"]
        assert run["timeout-minutes"] == 300
        assert run["env"]["MUTATION_SELECTOR"] == "${{ matrix.selector }}"
        gate = jobs["mutation"]
        assert gate["needs"] == "mutation-shards" and gate["if"] == "${{ always() }}"
        reject = gate["steps"][0]
        assert reject["if"] == "${{ needs.mutation-shards.result != 'success' }}"
        assert reject["run"] == "exit 1"
        assert not any(step.get("continue-on-error") for step in gate["steps"] + shard_job["steps"])
        commands = [step.get("run", "") for step in gate["steps"]]
        assert (
            "uv run --frozen python -m scripts.merge_mutation_results "
            "mutation-shards mutation-results.txt --catalogue audit/mutation-catalogue-v0.7.json"
            in commands
        )
        assert (
            commands[-1] == "uv run --frozen python scripts/check_mutation_score.py "
            "mutation-results.txt --minimum 85"
        )
