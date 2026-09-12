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
from scripts.mutation_selectors import PARTS, selectors

ROOT = Path(__file__).resolve().parents[1]


def reports(directory: Path, parts: int = 1) -> dict[str, str]:
    expected = {
        f"example.function__mutmut_{index}": "survived" if index == 1 else "killed"
        for index in range(1, 21)
    }
    for owner in range(SHARDS * parts):
        shard, part = owner % SHARDS, owner // SHARDS
        folder = directory / (f"mutation-shard-{shard}" + (f"-{part}" if parts > 1 else ""))
        folder.mkdir(parents=True)
        (folder / "mutation-results.txt").write_text(
            "".join(
                f"{name}: "
                + (
                    status
                    if int(name.rsplit("_", 1)[1]) % (SHARDS * parts) == owner
                    else "not checked"
                )
                + "\n"
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


def test_physical_parts_preserve_full_results_and_logical_owners(tmp_path: Path) -> None:
    directory = tmp_path / "parts"
    expected = reports(directory, PARTS)
    assert merge_results(directory, tmp_path / "catalogue.json", parts=PARTS) == expected
    for number in range(1, 10001):
        matches = [
            (shard, part)
            for shard in range(SHARDS)
            for part in range(PARTS)
            for pattern in selectors(shard, part)
            if fnmatch.fnmatchcase(f"module.fn__mutmut_{number}", pattern)
        ]
        assert matches == [(number % SHARDS, (number // SHARDS) % PARTS)]


@pytest.mark.parametrize(
    ("alteration", "code"),
    [
        ("missing", "mutation_shard_set_mismatch"),
        ("extra", "mutation_shard_set_mismatch"),
        ("incomplete", "mutation_shard_incomplete"),
        ("interrupted", "mutation_shard_incomplete"),
        ("overlap", "mutation_shard_overlap"),
        ("catalogue", "mutation_catalogue_mismatch"),
        ("duplicate", "mutation_result_duplicate"),
    ],
)
def test_physical_part_failures_are_not_masked(tmp_path: Path, alteration: str, code: str) -> None:
    directory = tmp_path / "parts"
    reports(directory, PARTS)
    path = directory / "mutation-shard-1-3/mutation-results.txt"
    content = path.read_text()
    if alteration == "missing":
        path.unlink()
        path.parent.rmdir()
    elif alteration == "extra":
        (directory / "mutation-shard-1-4").mkdir()
    elif alteration in {"incomplete", "interrupted"}:
        status = "not checked" if alteration == "incomplete" else "check was interrupted by user"
        path.write_text(content.replace("__mutmut_16: killed", f"__mutmut_16: {status}"))
    elif alteration == "overlap":
        path.write_text(content.replace("__mutmut_1: not checked", "__mutmut_1: killed"))
    elif alteration == "catalogue":
        path.write_text("\n".join(content.splitlines()[1:]))
    else:
        path.write_text(content + content.splitlines()[0] + "\n")
    with pytest.raises(ValueError, match=code):
        merge_results(directory, tmp_path / "catalogue.json", parts=PARTS)


def test_invalid_partition_counts_and_indices_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="mutation_partition_count_invalid"):
        merge_results(tmp_path, tmp_path / "absent", parts=2)
    for shard, part in ((-1, 0), (5, 0), (0, -1), (0, 4)):
        with pytest.raises(ValueError, match="mutation_partition_invalid"):
            selectors(shard, part)


def test_partition_cli_only_emits_validated_literal_selectors(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from scripts import mutation_selectors

    monkeypatch.setattr(sys, "argv", ["runner", "--shard", "1", "--part", "0"])
    assert mutation_selectors.main() == 0
    assert capsys.readouterr().out.splitlines() == selectors(1, 0)
    for value in ("1; echo injected", "$(echo injected)", "-1", "5"):
        monkeypatch.setattr(sys, "argv", ["runner", "--shard", value, "--part", "0"])
        with pytest.raises(SystemExit) as error:
            mutation_selectors.main()
        assert error.value.code == 2
        assert capsys.readouterr().out == ""


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
        matrix = shard_job["strategy"]["matrix"]
        assert shard_job["strategy"]["fail-fast"] is False
        assert matrix == {"shard": list(range(SHARDS)), "part": list(range(PARTS))}
        for number in range(1, 1001):
            mutant = f"example.function__mutmut_{number}"
            owners = [
                shard + SHARDS * part
                for shard in matrix["shard"]
                for part in matrix["part"]
                for pattern in selectors(shard, part)
                if fnmatch.fnmatchcase(mutant, pattern)
            ]
            assert owners == [number % (SHARDS * PARTS)]
        run = next(
            step for step in shard_job["steps"] if step.get("name") == "Run assigned mutants"
        )
        assert (
            'python -m scripts.mutation_selectors --shard "$MUTATION_SHARD" '
            '--part "$MUTATION_PART" > mutation-selectors.txt' in run["run"]
        )
        assert "mapfile -t mutation_selectors < mutation-selectors.txt" in run["run"]
        assert 'uv run --frozen mutmut run "${mutation_selectors[@]}"' in run["run"]
        assert run["working-directory"] == ".cache/mutation-workspace"
        assert "uv sync --frozen --all-extras --group dev --group security" in run["run"]
        preparation = next(
            step
            for step in shard_job["steps"]
            if step.get("name") == "Prepare isolated mutation layout"
        )
        assert preparation["run"] == (
            "uv run --frozen python -m scripts.prepare_mutation_workspace .cache/mutation-workspace"
        )
        assert run["timeout-minutes"] == 300
        assert run["env"] == {
            "MUTATION_SHARD": "${{ matrix.shard }}",
            "MUTATION_PART": "${{ matrix.part }}",
        }
        gate = jobs["mutation"]
        assert gate["needs"] == "mutation-shards"
        if name == "ci.yml":
            assert gate["if"] == "${{ always() }}"
            assert "if" not in shard_job
            assert shard_job["needs"] == [
                "core-platform",
                "quality-security",
                "postgres-integration",
            ]
        else:
            exception = (
                "github.event_name == 'release' && github.event.release.tag_name == 'v1.0.0' && "
                "vars.CPCF_MUTATION_EXCEPTION_VERSION == '1.0.0'"
            )
            assert shard_job["if"] == f"!({exception})"
            assert gate["if"] == f"always() && !({exception})"
            assert jobs["mutation-exception"]["if"] == exception
            assert jobs["mutation-exception"]["needs"] == "build"
        reject = gate["steps"][0]
        assert reject["if"] == "${{ needs.mutation-shards.result != 'success' }}"
        assert reject["run"] == "exit 1"
        assert not any(step.get("continue-on-error") for step in gate["steps"] + shard_job["steps"])
        commands = [step.get("run", "") for step in gate["steps"]]
        assert (
            "uv run --frozen python -m scripts.check_mutation_scope mutation-results.txt"
            in commands
        )
        assert (
            "uv run --frozen python -m scripts.merge_mutation_results "
            "mutation-shards mutation-results.txt --catalogue "
            "audit/mutation-catalogue-v1.0.json --parts 4" in commands
        )
        assert (
            commands[-1] == "uv run --frozen python scripts/check_mutation_score.py "
            "mutation-results.txt --minimum 85"
        )


def test_release_waiver_cannot_mask_other_failures_or_claim_a_mutation_pass() -> None:
    jobs = yaml.safe_load((ROOT / ".github/workflows/workflow.yml").read_text())["jobs"]
    for job_id in ("release-assets", "publish"):
        job = jobs[job_id]
        assert set(job["needs"]) >= {
            "build",
            "provenance",
            "mutation",
            "mutation-exception",
            "external-gates",
        }
        condition = job["if"]
        for dependency in ("build", "provenance", "external-gates"):
            assert f"needs.{dependency}.result == 'success' &&" in condition
        assert (
            "(needs.mutation.result == 'success' || "
            "(needs.mutation.result == 'skipped' && "
            "needs.mutation-exception.result == 'success' && "
            "github.event.release.tag_name == 'v1.0.0' && "
            "vars.CPCF_MUTATION_EXCEPTION_VERSION == '1.0.0')) &&" in condition
        )
        assert "github.event_name == 'release' &&" in condition
        assert "github.event.release.draft == false &&" in condition
        assert "github.event.release.prerelease == false" in condition
    assert "needs.release-assets.result == 'success' &&" in jobs["publish"]["if"]
    assert "vars.PYPI_PUBLISH_ENABLED == 'true'" in jobs["publish"]["if"]
    assert jobs["publish"]["environment"]["name"] == "pypi"
    record = jobs["mutation-exception"]["steps"][0]["run"]
    assert "WAIVED, NOT PASSED" in record and "native run was incomplete" in record
