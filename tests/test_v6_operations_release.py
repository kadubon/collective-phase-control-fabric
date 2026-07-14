# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from pathlib import Path

import pytest

from collective_phase_control_fabric.v6.canonical import canonical_bytes
from scripts.check_critical_coverage import GROUPS, evaluate
from scripts.check_external_release_evidence import REQUIRED_GATES, validate_manifest
from scripts.run_chaos_harness import run_scenarios
from scripts.run_load_harness import _bind_evidence, run_profile
from scripts.run_restore_harness import restore_round_trip

COMMIT = "a" * 40
DIGEST = "sha256:" + "b" * 64


def coverage_payload(score: int = 100) -> dict[str, object]:
    covered = score
    files = {
        name: {
            "summary": {
                "covered_lines": covered,
                "num_statements": 100,
                "covered_branches": covered,
                "num_branches": 100,
            }
        }
        for names in GROUPS.values()
        for name in names
    }
    return {"files": files}


def test_critical_coverage_is_enforced_per_named_group(tmp_path: Path) -> None:
    report = tmp_path / "coverage.json"
    report.write_text(json.dumps(coverage_payload()), encoding="utf-8")
    results = evaluate(report, 95.0)
    assert set(results) == set(GROUPS)
    assert all(value == 100.0 for value in results.values())

    failed = coverage_payload()
    failed["files"][GROUPS["planning"][0]]["summary"]["covered_branches"] = 0  # type: ignore[index]
    report.write_text(json.dumps(failed), encoding="utf-8")
    with pytest.raises(ValueError, match="planning"):
        evaluate(report, 95.0)

    missing = coverage_payload()
    del missing["files"][GROUPS["trials"][0]]  # type: ignore[index]
    report.write_text(json.dumps(missing), encoding="utf-8")
    with pytest.raises(ValueError, match="trials:missing"):
        evaluate(report, 95.0)


def valid_release_manifest() -> dict[str, object]:
    gates = []
    for name in sorted(REQUIRED_GATES):
        details: dict[str, object] = {}
        if name == "availability_soak":
            details["duration_seconds"] = 2_592_000
        if name == "backup_restore":
            details["intended_deployment"] = True
        if name == "penetration_test":
            details["open_blocking_findings"] = 0
        gates.append(
            {
                "name": name,
                "passed": True,
                "independent": name in {"threat_model_review", "penetration_test"},
                "evidence_digest": DIGEST,
                "details": details,
            }
        )
    return {
        "schema_version": "cpcf.io/release-evidence/v1",
        "release_version": "0.6.0",
        "commit_sha": COMMIT,
        "gates": gates,
    }


def test_external_release_evidence_requires_every_bound_independent_gate() -> None:
    assert not validate_manifest(valid_release_manifest(), version="0.6.0", commit=COMMIT)
    invalid = valid_release_manifest()
    gates = invalid["gates"]
    assert isinstance(gates, list)
    penetration = next(item for item in gates if item["name"] == "penetration_test")
    penetration["independent"] = False
    penetration["details"]["open_blocking_findings"] = 1
    soak = next(item for item in gates if item["name"] == "availability_soak")
    soak["details"]["duration_seconds"] = 100
    restore = next(item for item in gates if item["name"] == "backup_restore")
    restore["details"]["intended_deployment"] = False
    reasons = validate_manifest(invalid, version="0.6.0", commit="c" * 40)
    assert {
        "release_evidence_commit_mismatch",
        "release_gate_independence_required:penetration_test",
        "penetration_test_blocking_findings_open",
        "availability_soak_shorter_than_30_days",
        "restore_not_run_in_intended_deployment",
    }.issubset(reasons)

    malformed = valid_release_manifest()
    malformed_gates = malformed["gates"]
    assert isinstance(malformed_gates, list)
    malformed_gates.pop()
    malformed_gates[0]["independent"] = "yes"
    malformed_gates.append(
        {
            "name": "unregistered_gate",
            "passed": True,
            "independent": False,
            "evidence_digest": DIGEST,
            "details": {},
        }
    )
    malformed_reasons = validate_manifest(malformed, version="0.6.0", commit=COMMIT)
    assert any(reason.startswith("release_evidence_gates_missing:") for reason in malformed_reasons)
    assert "release_evidence_gates_unexpected:unregistered_gate" in malformed_reasons
    assert any(
        reason.startswith("release_gate_independence_invalid:") for reason in malformed_reasons
    )


def test_beta_package_publication_does_not_invent_operational_evidence(tmp_path: Path) -> None:
    command = [
        sys.executable,
        "scripts/check_external_release_evidence.py",
        str(tmp_path / "absent.json"),
        "--version",
        "0.6.0",
        "--commit",
        COMMIT,
    ]
    strict = subprocess.run(command, check=False, capture_output=True, text=True)
    assert strict.returncode == 1
    assert "missing or invalid" in strict.stderr

    beta = subprocess.run(
        [*command, "--publication-class", "beta"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert beta.returncode == 0
    assert "beta package publication accepted" in beta.stdout
    assert "operational-assurance evidence is unavailable" in beta.stdout


def test_reference_operations_harness_runs_exact_selected_scale_without_external_claims() -> None:
    load = asyncio.run(run_profile(100, 10_000, 100, 100))
    assert load["profile"] == {
        "tenants": 100,
        "workspaces": 10_000,
        "concurrent_audit_admissions": 100,
        "task_concurrency": 100,
    }
    assert load["observations"]["cross_tenant_job_isolation"] == "passed"
    assert load["targets"]["audit_admission_target_met"] is True
    assert _bind_evidence(load)["evidence_digest"].startswith("sha256:")
    scenarios = run_scenarios()
    assert len(scenarios) == 5
    assert all(item["status"] == "passed" for item in scenarios)
    restore = restore_round_trip()
    assert restore["tenant_count"] == 2
    assert restore["generation_and_history_binding"] == "passed"
    assert canonical_bytes(restore)


@pytest.mark.parametrize(
    ("tenants", "workspaces", "audits", "concurrency"),
    [(0, 1, 1, 1), (2, 1, 1, 1), (1, 2, 3, 1), (1, 1, 1, 0), (1, 1, 1, 1001)],
)
def test_load_harness_rejects_unbounded_or_inconsistent_profiles(
    tenants: int, workspaces: int, audits: int, concurrency: int
) -> None:
    with pytest.raises(ValueError):
        asyncio.run(run_profile(tenants, workspaces, audits, concurrency))


def test_release_workflow_fails_closed_on_external_and_per_group_gates() -> None:
    workflow = Path(".github/workflows/workflow.yml").read_text(encoding="utf-8")
    ci = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    for source in (workflow, ci):
        assert "check_critical_coverage.py" in source
        assert "critical-coverage.json" in source
    assert "external-gates:" in workflow
    assert "check_external_release_evidence.py" in workflow
    assert "--publication-class beta" in workflow
    assert "needs: [build, provenance, mutation, external-gates]" in workflow
    assert "PYPI_PUBLISH_ENABLED == 'true'" in workflow
    security = Path(".github/workflows/security.yml").read_text(encoding="utf-8")
    assert security.count("id: api-image-scan") == 1
    assert security.count("id: worker-image-scan") == 1
    assert "docker build --target api" in security
    assert "docker build --target worker" in security
    assert "hashFiles('trivy-api-image.sarif') != ''" in security
    assert "hashFiles('trivy-worker-image.sarif') != ''" in security
    assert 'test "$API_SCAN" = success && test "$WORKER_SCAN" = success' in security


def test_service_images_install_runtime_and_provider_extras() -> None:
    api = Path("deploy/Dockerfile.api").read_text(encoding="utf-8")
    worker = Path("deploy/Dockerfile.worker").read_text(encoding="utf-8")
    assert "--extra server" in api
    assert "--extra worker" in worker
    for provider in ("aws-kms", "gcp-kms", "azure-kms", "pkcs11"):
        assert f"--extra {provider}" in api
        assert f"--extra {provider}" in worker
    assert "FROM api-core AS api" in api
    assert "FROM worker-core AS worker" in worker
    for source in (api, worker):
        assert "COPY AGENTS.md llms.txt agent-manifest.json SPEC.md FORMAL_MODEL.md ./" in source
        assert "COPY fixtures ./fixtures" in source
        assert "COPY docs ./docs" in source


def test_helm_defaults_fail_closed_for_incomplete_privileged_components() -> None:
    values = Path("deploy/helm/cpcf/values.yaml").read_text(encoding="utf-8")
    worker = Path("deploy/helm/cpcf/templates/worker.yaml").read_text(encoding="utf-8")
    migration = Path("deploy/helm/cpcf/templates/migration.yaml").read_text(encoding="utf-8")
    accounts = Path("deploy/helm/cpcf/templates/serviceaccount.yaml").read_text(encoding="utf-8")
    assert values.count("enabled: false") >= 2
    assert "worker.tenantId is required" in worker
    assert "database-owner-url" in migration
    assert "migration.enabled" in migration
    assert "cpcf-api" in accounts and "cpcf-worker" in accounts and "cpcf-migration" in accounts
