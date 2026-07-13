# SPDX-License-Identifier: Apache-2.0
"""English-first CPCF v0.6 CLI and read-only legacy bridge."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

from collective_phase_control_fabric import __version__
from collective_phase_control_fabric.bundle import verify_bundle
from collective_phase_control_fabric.v6.canonical import digest_bytes, loads_bounded
from collective_phase_control_fabric.v6.catalog import AGENT_GUIDANCE
from collective_phase_control_fabric.v6.models import (
    CapabilityDocument,
    ExecutionPolicy,
    RunnerJob,
    RunnerReceipt,
)
from collective_phase_control_fabric.v6.registry import (
    DocumentValidationError,
    parse_document_bytes,
    registry_manifest,
    schema_for_kind,
)
from collective_phase_control_fabric.v6.runner import validate_receipt
from cpcf_cli.auth import device_login, stored_token

FALLBACK_CLAIM_KEY = "cpcf_token_environment_fallback_supported"

LEGACY_READ_ONLY_COMMANDS = frozenset(
    {
        ("agent", "explain"),
        ("agent", "next"),
        ("agent", "onboard"),
        ("agent", "why"),
        ("attestation", "inspect"),
        ("contract", "explain-missing"),
        ("contract", "validate"),
        ("doctor",),
        ("execution", "inspect-risk"),
        ("intervention", "analyze"),
        ("perturbation", "replay"),
        ("phase", "inspect"),
        ("projection", "pending"),
        ("repair", "list"),
        ("repair", "show"),
        ("schema", "list"),
        ("schema", "show"),
        ("science", "audit"),
        ("source", "inspect"),
        ("time", "inspect"),
        ("trial", "amendment-inspect"),
        ("trial", "inspect"),
        ("trial", "protocol-inspect"),
        ("trust", "genesis-inspect"),
        ("trust", "quorum-inspect"),
        ("trust", "validate"),
        ("workspace", "status"),
    }
)


def _legacy_command_is_read_only(arguments: list[str]) -> bool:
    if "--apply" in arguments:
        return False
    positional = tuple(item for item in arguments if not item.startswith("-"))
    return any(positional[: len(command)] == command for command in LEGACY_READ_ONLY_COMMANDS)


def _local_response(
    *,
    status: str,
    code: str,
    claims: dict[str, Any] | None = None,
    unknowns: list[str] | None = None,
    next_safe_commands: list[list[str]] | None = None,
) -> dict[str, Any]:
    return {
        "status": status,
        "code": code,
        "effect_class": "inspect",
        "tenant_id": None,
        "workspace_id": None,
        "generation_digest": None,
        "job_id": None,
        "objects_written": [],
        "authority_required": [],
        "claims": claims or {},
        "unknowns": unknowns or [],
        "quarantined_objects": [],
        "next_safe_commands": next_safe_commands or [],
        "trace_id": "local-cli",
    }


def _emit(value: Any) -> int:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0 if value.get("status") in {"ok", "accepted", "queued", "blocked"} else 1


def _headers(
    *,
    mutation: bool = False,
    generation: str | None = None,
    authenticated: bool = True,
) -> dict[str, str]:
    token = stored_token()
    if authenticated and not token:
        raise RuntimeError("OIDC login or CPCF_TOKEN is required")
    result = {"Authorization": f"Bearer {token}"} if token else {}
    if mutation:
        result["Idempotency-Key"] = os.environ.get("CPCF_IDEMPOTENCY_KEY", os.urandom(16).hex())
    if generation is not None:
        result["If-Match"] = generation
    return result


def _request(
    method: str,
    path: str,
    *,
    body: dict[str, Any] | None = None,
    content: bytes | None = None,
    mutation: bool = False,
    generation: str | None = None,
    authenticated: bool = True,
) -> int:
    base = os.environ.get("CPCF_API_URL", "https://localhost:8443").rstrip("/")
    try:
        with httpx.Client(timeout=30.0, follow_redirects=False) as client:
            response = client.request(
                method,
                base + path,
                json=body,
                content=content,
                headers=_headers(
                    mutation=mutation,
                    generation=generation,
                    authenticated=authenticated,
                ),
            )
        value = response.json()
    except (httpx.HTTPError, RuntimeError, ValueError) as error:
        return _emit(
            {
                "status": "error",
                "code": "control_plane_unavailable",
                "effect_class": "none",
                "claims": {},
                "unknowns": [str(error)],
                "objects_written": [],
                "authority_required": [],
                "quarantined_objects": [],
                "next_safe_commands": [["cpcf", "auth", "login", "--json"]],
                "trace_id": "local-cli",
            }
        )
    return _emit(value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cpcf",
        description=(
            "Evidence-bound control of finite collective workflows. CPCF does not infer or "
            "claim collective superintelligence."
        ),
    )
    parser.add_argument("--version", action="version", version=f"cpcf {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    self_check = commands.add_parser(
        "self-check", help="Validate the installed offline core without contacting an API."
    )

    auth = commands.add_parser("auth", help="Inspect OIDC client configuration.")
    auth_sub = auth.add_subparsers(dest="subcommand", required=True)
    login = auth_sub.add_parser(
        "login", help="Use OIDC device authorization and an OS-backed credential store."
    )

    schema = commands.add_parser("schema", help="Inspect the closed v0.6 schema registry.")
    schema_sub = schema.add_subparsers(dest="subcommand", required=True)
    schema_list = schema_sub.add_parser("list", help="List locally installed v0.6 schemas.")
    show = schema_sub.add_parser("show", help="Show one locally generated v0.6 schema.")
    show.add_argument("kind")

    bundle = commands.add_parser("bundle", help="Verify a portable bundle without network access.")
    bundle_sub = bundle.add_subparsers(dest="subcommand", required=True)
    bundle_verify = bundle_sub.add_parser(
        "verify", help="Verify bundle content and optional trust."
    )
    bundle_verify.add_argument("bundle", type=Path)
    bundle_verify.add_argument("--trust-policy", type=Path)

    workspace = commands.add_parser("workspace", help="Create and inspect tenant workspaces.")
    workspace_sub = workspace.add_subparsers(dest="subcommand", required=True)
    create = workspace_sub.add_parser(
        "create", help="Create a workspace with two out-of-band genesis fingerprints."
    )
    create.add_argument("workspace")
    create.add_argument("--root-spki-fingerprint", required=True)
    create.add_argument("--genesis-envelope-fingerprint", required=True)
    status_parser = workspace_sub.add_parser("status")
    status_parser.add_argument("workspace")
    import_legacy = workspace_sub.add_parser(
        "import-legacy", help="Queue copy-on-write import of uploaded legacy material."
    )

    object_command = commands.add_parser("object", help="Upload immutable CAS material.")
    object_sub = object_command.add_subparsers(dest="subcommand", required=True)
    upload = object_sub.add_parser("upload")
    upload.add_argument("workspace")
    upload.add_argument("path", type=Path)
    upload.add_argument("--generation", required=True)
    admit_object = object_sub.add_parser("admit", help="Queue signed object admission.")

    remote_items: list[argparse.ArgumentParser] = []

    def mutation_leaf(
        item: argparse.ArgumentParser,
        path: str,
        *,
        include_session: bool = False,
        include_scenario: bool = False,
    ) -> None:
        item.add_argument("workspace")
        item.add_argument("--generation", required=True)
        item.add_argument("--digest", action="append", default=[])
        if include_session:
            item.add_argument("--session")
        if include_scenario:
            item.add_argument("--scenario")
        item.set_defaults(remote_method="POST", remote_path=path, remote_mutation=True)
        remote_items.append(item)

    def inspection_leaf(item: argparse.ArgumentParser, path: str) -> None:
        item.add_argument("workspace")
        item.set_defaults(remote_method="GET", remote_path=path, remote_mutation=False)
        remote_items.append(item)

    mutation_leaf(
        import_legacy,
        "/v1/workspaces/{workspace}/objects/admissions",
    )
    mutation_leaf(admit_object, "/v1/workspaces/{workspace}/objects/admissions")

    attestation = commands.add_parser("attestation", help="Admit typed signed statements.")
    attestation_sub = attestation.add_subparsers(dest="subcommand", required=True)
    mutation_leaf(
        attestation_sub.add_parser("admit"),
        "/v1/workspaces/{workspace}/objects/admissions",
    )

    trust = commands.add_parser("trust", help="Inspect or queue role-separated trust updates.")
    trust_sub = trust.add_subparsers(dest="subcommand", required=True)
    inspection_leaf(
        trust_sub.add_parser("status"),
        "/v1/workspaces/{workspace}/onboarding",
    )
    mutation_leaf(
        trust_sub.add_parser("update"),
        "/v1/workspaces/{workspace}/trust/updates",
    )

    time_command = commands.add_parser("time", help="Inspect or admit trusted-time receipts.")
    time_sub = time_command.add_subparsers(dest="subcommand", required=True)
    inspection_leaf(
        time_sub.add_parser("status"),
        "/v1/workspaces/{workspace}/onboarding",
    )
    mutation_leaf(
        time_sub.add_parser("update"),
        "/v1/workspaces/{workspace}/time/receipts",
    )

    perturbation = commands.add_parser("perturbation", help="Replay a reduced immutable snapshot.")
    perturbation_sub = perturbation.add_subparsers(dest="subcommand", required=True)
    mutation_leaf(
        perturbation_sub.add_parser("replay"),
        "/v1/workspaces/{workspace}/perturbations",
        include_scenario=True,
    )

    intervention = commands.add_parser("intervention", help="Queue bounded intervention analysis.")
    intervention_sub = intervention.add_subparsers(dest="subcommand", required=True)
    mutation_leaf(
        intervention_sub.add_parser("analyze"),
        "/v1/workspaces/{workspace}/interventions",
    )

    action = commands.add_parser("action", help="Dispatch one signed action to a runner queue.")
    action_sub = action.add_subparsers(dest="subcommand", required=True)
    mutation_leaf(
        action_sub.add_parser("dispatch"),
        "/v1/workspaces/{workspace}/actions",
    )

    projection = commands.add_parser("projection", help="Inspect and approve pending projections.")
    projection_sub = projection.add_subparsers(dest="subcommand", required=True)
    inspection_leaf(
        projection_sub.add_parser("pending"),
        "/v1/workspaces/{workspace}/collections/projections",
    )
    mutation_leaf(
        projection_sub.add_parser("approve"),
        "/v1/workspaces/{workspace}/projections/approvals",
    )

    coordination = commands.add_parser("coordination", help="Advance signed coordination sessions.")
    coordination_sub = coordination.add_subparsers(dest="subcommand", required=True)
    for operation in ("init", "commit", "reveal", "route", "terminate"):
        mutation_leaf(
            coordination_sub.add_parser(operation),
            f"/v1/workspaces/{{workspace}}/coordination/{operation}",
            include_session=True,
        )
    inspection_leaf(
        coordination_sub.add_parser("status"),
        "/v1/workspaces/{workspace}/collections/coordination",
    )

    trial = commands.add_parser("trial", help="Admit and inspect preregistered external evidence.")
    trial_sub = trial.add_subparsers(dest="subcommand", required=True)
    for operation in ("protocol-import", "amendment-import", "result-import"):
        mutation_leaf(
            trial_sub.add_parser(operation),
            f"/v1/workspaces/{{workspace}}/trials/{operation}",
        )
    inspection_leaf(
        trial_sub.add_parser("status"),
        "/v1/workspaces/{workspace}/collections/trials",
    )

    quarantine = commands.add_parser("quarantine", help="Inspect or queue quarantine changes.")
    quarantine_sub = quarantine.add_subparsers(dest="subcommand", required=True)
    inspection_leaf(
        quarantine_sub.add_parser("list"),
        "/v1/workspaces/{workspace}/collections/quarantine",
    )
    mutation_leaf(
        quarantine_sub.add_parser("resolve"),
        "/v1/workspaces/{workspace}/quarantine/actions",
    )

    repair = commands.add_parser("repair", help="Inspect typed repairs or run a bound action.")
    repair_sub = repair.add_subparsers(dest="subcommand", required=True)
    inspection_leaf(
        repair_sub.add_parser("list"),
        "/v1/workspaces/{workspace}/collections/repairs",
    )
    show_repair = repair_sub.add_parser("show")
    show_repair.add_argument("repair_id")
    inspection_leaf(show_repair, "/v1/workspaces/{workspace}/collections/repairs")
    run_repair = repair_sub.add_parser("run")
    run_repair.add_argument("repair_id")
    mutation_leaf(
        run_repair,
        "/v1/workspaces/{workspace}/repairs/{repair_id}/actions",
    )

    audit = commands.add_parser("audit", help="Queue or inspect immutable snapshot audits.")
    audit_sub = audit.add_subparsers(dest="subcommand", required=True)
    start = audit_sub.add_parser("start")
    start.add_argument("workspace")
    start.add_argument("--generation", required=True)
    job_status = audit_sub.add_parser("status")
    job_status.add_argument("job_id")

    runner = commands.add_parser("runner", help="Validate signed runner protocol records.")
    runner_sub = runner.add_subparsers(dest="subcommand", required=True)
    conformance = runner_sub.add_parser(
        "conformance", help="Validate one local job/receipt contract without execution."
    )
    conformance.add_argument("job", type=Path)
    conformance.add_argument("receipt", type=Path)
    conformance.add_argument("capability", type=Path)
    conformance.add_argument("execution_policy", type=Path)
    conformance.add_argument("--runner-principal", required=True)
    conformance.add_argument("--received-at", required=True)
    conformance.add_argument("--artifact", action="append", default=[], metavar="DIGEST=PATH")

    agent = commands.add_parser("agent", help="Obtain evidence-driven onboarding instructions.")
    agent_sub = agent.add_subparsers(dest="subcommand", required=True)
    explain = agent_sub.add_parser(
        "explain", help="Explain CPCF claims, nonclaims, and the first safe offline commands."
    )
    onboard = agent_sub.add_parser("onboard")
    onboard.add_argument("--workspace", required=True)

    legacy = commands.add_parser("legacy", help="Read-only v0.1-v0.5 inspection.")
    legacy_sub = legacy.add_subparsers(dest="subcommand", required=True)
    legacy_inspect = legacy_sub.add_parser("inspect")
    legacy_inspect.add_argument("arguments", nargs=argparse.REMAINDER)

    for item in (
        self_check,
        login,
        schema_list,
        show,
        bundle_verify,
        explain,
        create,
        status_parser,
        upload,
        start,
        job_status,
        conformance,
        onboard,
        *remote_items,
    ):
        item.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    return parser


def _self_check() -> int:
    failures: list[str] = []
    manifest = registry_manifest()
    schemas = manifest.get("schemas", [])
    if not isinstance(schemas, list) or not schemas:
        failures.append("schema_registry_empty")
    else:
        for item in schemas:
            try:
                if not isinstance(item, dict) or not isinstance(item.get("kind"), str):
                    raise DocumentValidationError("schema_manifest_entry_invalid")
                generated = schema_for_kind(item["kind"])
                if generated.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
                    failures.append(f"schema_dialect_invalid:{item['kind']}")
            except DocumentValidationError as error:
                failures.append(error.code)
    python_supported = (3, 12) <= sys.version_info[:2] < (3, 15) and sys.version_info[:3] not in {
        (3, 14, 0),
        (3, 14, 1),
    }
    if not python_supported:
        failures.append("python_version_unsupported")

    def available(module: str) -> bool:
        try:
            return importlib.util.find_spec(module) is not None
        except ModuleNotFoundError:
            return False

    extras = {
        "server": available("fastapi"),
        "solver": available("z3"),
        "aws_kms": available("boto3"),
        "gcp_kms": available("google.cloud.kms"),
        "azure_kms": available("azure.keyvault.keys"),
        "pkcs11": available("pkcs11"),
    }
    return _emit(
        _local_response(
            status="ok" if not failures else "error",
            code="offline_self_check_passed" if not failures else "offline_self_check_failed",
            claims={
                "distribution": "collective-phase-control-fabric",
                "version": __version__,
                "python": platform.python_version(),
                "schema_count": len(schemas) if isinstance(schemas, list) else 0,
                "offline_core_available": not failures,
                "optional_extras": extras,
                "external_effect": False,
            },
            unknowns=failures,
            next_safe_commands=[
                ["cpcf", "agent", "explain", "--json"],
                ["cpcf", "schema", "list", "--json"],
            ]
            if not failures
            else [],
        )
    )


def _explain() -> int:
    claims = dict(AGENT_GUIDANCE)
    next_commands = claims.pop("first_safe_commands")
    return _emit(
        _local_response(
            status="ok",
            code="offline_orientation",
            claims=claims,
            next_safe_commands=next_commands,  # type: ignore[arg-type]
        )
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "self-check":
        return _self_check()
    if args.command == "auth":
        result = device_login()
        return _emit(
            {
                "status": result.status,
                "code": result.code,
                "effect_class": "local_write" if result.status == "ok" else "none",
                "claims": {
                    "credential_storage": "os_keyring_only",
                    "verification_uri": result.verification_uri,
                    "user_code": result.user_code,
                    "account": result.account,
                    FALLBACK_CLAIM_KEY: True,
                },
                "unknowns": [],
                "objects_written": [],
                "authority_required": ["oidc_identity"],
                "quarantined_objects": [],
                "next_safe_commands": [],
                "trace_id": "local-cli",
            }
        )
    if args.command == "schema":
        if args.subcommand == "list":
            return _emit(
                _local_response(
                    status="ok",
                    code="schema_registry",
                    claims=registry_manifest(),
                )
            )
        try:
            schema = schema_for_kind(args.kind)
        except DocumentValidationError as error:
            return _emit(
                _local_response(
                    status="error",
                    code=error.code,
                    unknowns=[error.detail] if error.detail else [],
                    next_safe_commands=[["cpcf", "schema", "list", "--json"]],
                )
            )
        return _emit(
            _local_response(
                status="ok",
                code="schema_document",
                claims={"kind": args.kind, "schema": schema},
            )
        )
    if args.command == "bundle":
        checked = verify_bundle(args.bundle, args.trust_policy)
        valid = checked.get("valid") is True
        return _emit(
            _local_response(
                status="ok" if valid else "error",
                code="bundle_content_verified" if valid else "bundle_verification_failed",
                claims=checked,
                unknowns=["distribution_authenticity"]
                if checked.get("authenticity_status") == "unknown"
                else [],
            )
        )
    remote_path = getattr(args, "remote_path", None)
    if isinstance(remote_path, str):
        try:
            request_path = remote_path.format(
                workspace=args.workspace,
                repair_id=getattr(args, "repair_id", ""),
            )
        except (AttributeError, KeyError, ValueError):
            return _emit(_local_response(status="error", code="remote_command_arguments_invalid"))
        mutation = bool(getattr(args, "remote_mutation", False))
        body = None
        if mutation:
            body = {
                "subject_digests": list(getattr(args, "digest", [])),
            }
            session = getattr(args, "session", None)
            scenario = getattr(args, "scenario", None)
            if session is not None:
                body["session_id"] = session
            if scenario is not None:
                body["scenario_id"] = scenario
        return _request(
            str(args.remote_method),
            request_path,
            body=body,
            mutation=mutation,
            generation=getattr(args, "generation", None),
        )
    if args.command == "workspace":
        if args.subcommand == "create":
            return _request(
                "POST",
                "/v1/workspaces",
                body={
                    "workspace_id": args.workspace,
                    "root_spki_fingerprint": args.root_spki_fingerprint,
                    "genesis_envelope_fingerprint": args.genesis_envelope_fingerprint,
                },
                mutation=True,
            )
        return _request("GET", f"/v1/workspaces/{args.workspace}")
    if args.command == "audit":
        if args.subcommand == "start":
            return _request(
                "POST",
                f"/v1/workspaces/{args.workspace}/analyses",
                body={},
                mutation=True,
                generation=args.generation,
            )
        return _request("GET", f"/v1/jobs/{args.job_id}")
    if args.command == "object":
        input_path: Path = args.path
        if not input_path.is_file() or input_path.stat().st_size > 64 * 1024 * 1024:
            return _emit(
                _local_response(
                    status="error",
                    code="cas_upload_input_invalid",
                    unknowns=["path_must_be_a_file_not_larger_than_64_mib"],
                )
            )
        content = input_path.read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        return _request(
            "PUT",
            f"/v1/workspaces/{args.workspace}/cas/sha256/{digest}",
            content=content,
            mutation=True,
            generation=args.generation,
        )
    if args.command == "runner":
        try:
            job = parse_document_bytes(args.job.read_bytes())
            receipt = parse_document_bytes(args.receipt.read_bytes())
            capability = parse_document_bytes(args.capability.read_bytes())
            execution_policy = parse_document_bytes(args.execution_policy.read_bytes())
            if not isinstance(job, RunnerJob):
                raise ValueError("runner_job_document_required")
            if not isinstance(receipt, RunnerReceipt):
                raise ValueError("runner_receipt_document_required")
            if not isinstance(capability, CapabilityDocument):
                raise ValueError("runner_capability_document_required")
            if not isinstance(execution_policy, ExecutionPolicy):
                raise ValueError("runner_execution_policy_document_required")
            available: set[str] = set()
            artifact_lengths: dict[str, int] = {}
            artifact_values: dict[str, bytes] = {}
            for binding in args.artifact:
                digest, separator, path_value = binding.partition("=")
                if not separator or not digest.startswith("sha256:"):
                    raise ValueError("runner_artifact_binding_invalid")
                artifact_path = Path(path_value)
                if not artifact_path.is_file() or artifact_path.stat().st_size > 64 * 1024 * 1024:
                    raise ValueError("runner_artifact_binding_invalid")
                data = artifact_path.read_bytes()
                if digest_bytes(data) != digest or digest in available:
                    raise ValueError("runner_artifact_digest_invalid")
                available.add(digest)
                artifact_lengths[digest] = len(data)
                artifact_values[digest] = data
            output_document = None
            if len(receipt.spec.output_digests) == 1:
                output_document = loads_bounded(artifact_values[receipt.spec.output_digests[0]])
            runner_checked = validate_receipt(
                job,
                receipt,
                capability,
                execution_policy,
                received_at=datetime.fromisoformat(args.received_at),
                expected_runner_principal_id=args.runner_principal,
                prior_attempts=set(),
                available_digests=available,
                artifact_lengths=artifact_lengths,
                output_document=output_document,
            )
        except (KeyError, OSError, TypeError, ValueError) as error:
            code = str(error)
            if not re.fullmatch(r"[a-z0-9_:-]{1,128}", code):
                code = "runner_conformance_input_invalid"
            return _emit(
                _local_response(
                    status="error",
                    code=code,
                    unknowns=["runner_contract_not_evaluated"],
                )
            )
        return _emit(
            _local_response(
                status="ok" if runner_checked.accepted else "error",
                code=runner_checked.code,
                claims={
                    "accepted": runner_checked.accepted,
                    "reasons": runner_checked.reasons,
                },
                unknowns=[] if runner_checked.accepted else runner_checked.reasons,
            )
        )
    if args.command == "agent":
        if args.subcommand == "explain":
            return _explain()
        return _request("GET", f"/v1/workspaces/{args.workspace}/onboarding")
    if args.command == "legacy":
        if not _legacy_command_is_read_only(args.arguments):
            return _emit(
                _local_response(
                    status="error",
                    code="legacy_mutation_blocked",
                    unknowns=["legacy_authority_objects_are_quarantined"],
                    next_safe_commands=[["cpcf", "legacy", "inspect", "doctor", "--json"]],
                )
            )
        from collective_phase_control_fabric.cli import main as legacy_main

        previous = sys.argv
        try:
            sys.argv = ["cpcf", *args.arguments]
            return legacy_main()
        finally:
            sys.argv = previous
    return 2


if __name__ == "__main__":
    sys.exit(main())
