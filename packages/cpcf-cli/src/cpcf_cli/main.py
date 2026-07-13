# SPDX-License-Identifier: Apache-2.0
"""English-first CPCF v0.6 CLI and read-only legacy bridge."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import sys
from pathlib import Path
from typing import Any

import httpx

from collective_phase_control_fabric import __version__
from collective_phase_control_fabric.bundle import verify_bundle
from collective_phase_control_fabric.v6.catalog import AGENT_GUIDANCE
from collective_phase_control_fabric.v6.registry import (
    DocumentValidationError,
    registry_manifest,
    schema_for_kind,
)


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
    token = os.environ.get("CPCF_TOKEN")
    if authenticated and not token:
        raise RuntimeError("CPCF_TOKEN is required; the CLI does not persist bearer tokens")
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
    login = auth_sub.add_parser("login", help="Explain the non-persistent bearer-token boundary.")

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
    create = workspace_sub.add_parser("create")
    create.add_argument("workspace")
    status_parser = workspace_sub.add_parser("status")
    status_parser.add_argument("workspace")

    audit = commands.add_parser("audit", help="Queue or inspect immutable snapshot audits.")
    audit_sub = audit.add_subparsers(dest="subcommand", required=True)
    start = audit_sub.add_parser("start")
    start.add_argument("workspace")
    start.add_argument("--generation", required=True)
    job_status = audit_sub.add_parser("status")
    job_status.add_argument("job_id")

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
        start,
        job_status,
        onboard,
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
        return _emit(
            {
                "status": "blocked" if "CPCF_TOKEN" not in os.environ else "ok",
                "code": "bearer_token_required"
                if "CPCF_TOKEN" not in os.environ
                else "token_present",
                "effect_class": "inspect",
                "claims": {"credential_storage": "environment_only"},
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
    if args.command == "workspace":
        if args.subcommand == "create":
            return _request(
                "POST",
                "/v1/workspaces",
                body={"workspace_id": args.workspace},
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
    if args.command == "agent":
        if args.subcommand == "explain":
            return _explain()
        return _request("GET", f"/v1/workspaces/{args.workspace}/onboarding")
    if args.command == "legacy":
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
