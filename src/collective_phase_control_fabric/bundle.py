# SPDX-License-Identifier: Apache-2.0
"""Portable bundle creation and content verification."""

from __future__ import annotations

import shutil
from pathlib import Path

from collective_phase_control_fabric.canonical import digest_bytes, write_canonical
from collective_phase_control_fabric.types import JsonObject


def create_bundle(workspace: Path, bundle: Path) -> JsonObject:
    """Copy the finite receipt chain and projections needed for offline verification."""

    bundle.mkdir(parents=True, exist_ok=True)
    from collective_phase_control_fabric.workspace_v4 import workspace_version

    native_version = workspace_version(workspace)
    native_generation = native_version in {"0.3.0", "0.4.0"}
    names = [] if native_generation else ["contract.json", "network.json", "actions.json"]
    names.extend(
        name
        for name in ("productive_witness.json", "maintenance_witness.json")
        if (workspace / name).is_file()
    )
    relative_roots = (
        (".cpcf/cas", ".cpcf/generations")
        if native_generation
        else (
            "actions",
            "adapter-capabilities",
            "witnesses",
            ".cpcf/cas",
            ".cpcf/envelopes",
            ".cpcf/receipts",
            ".cpcf/projections",
            ".cpcf/transitions",
        )
    )
    for relative_root in relative_roots:
        source_root = workspace / relative_root
        if source_root.is_dir():
            names.extend(
                str(path.relative_to(workspace)).replace("\\", "/")
                for path in source_root.rglob("*")
                if path.is_file()
            )
    if native_generation:
        names.append(".cpcf/CURRENT")
    else:
        names.extend(
            name
            for name in (".cpcf/workspace.json", ".cpcf/history.json")
            if (workspace / name).is_file()
        )
    objects: list[JsonObject] = []
    for name in sorted(names):
        source = workspace / name
        workspace_root = workspace.resolve()
        resolved_source = source.resolve()
        if workspace_root not in resolved_source.parents:
            raise ValueError(f"bundle source escapes workspace: {name}")
        destination = bundle / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        data = destination.read_bytes()
        objects.append({"path": name, "digest": digest_bytes(data), "size": len(data)})
    manifest: JsonObject = {
        "bundle_schema_version": native_version if native_generation else "0.2.0",
        "objects": objects,
        "portable": True,
        "source_of_record_migrated": False,
    }
    write_canonical(bundle / "manifest.json", manifest)
    return manifest


def verify_bundle(bundle: Path, trust_policy: Path | None = None) -> JsonObject:
    """Verify every manifest object while rejecting path traversal."""

    from collective_phase_control_fabric.canonical import load_json

    manifest_value = load_json(bundle / "manifest.json")
    if not isinstance(manifest_value, dict) or not isinstance(manifest_value.get("objects"), list):
        return {"command_status": "failed", "valid": False, "errors": ["manifest_malformed"]}
    errors: list[str] = []
    root = bundle.resolve()
    seen_paths: set[str] = set()
    for item in manifest_value["objects"]:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            errors.append("object_entry_malformed")
            continue
        relative = item["path"]
        if relative in seen_paths:
            errors.append(f"duplicate_object_path:{relative}")
            continue
        seen_paths.add(relative)
        path = (root / relative).resolve()
        if root not in path.parents:
            errors.append(f"path_escape:{item['path']}")
            continue
        if not path.is_file():
            errors.append(f"object_missing:{item['path']}")
            continue
        data = path.read_bytes()
        if digest_bytes(data) != item.get("digest"):
            errors.append(f"digest_mismatch:{item['path']}")
        if len(data) != item.get("size"):
            errors.append(f"size_mismatch:{item['path']}")
    generation_errors: list[JsonObject] = []
    doctor_errors: list[JsonObject] = []
    bundle_version = manifest_value.get("bundle_schema_version")
    if bundle_version in {"0.3.0", "0.4.0"} and not errors:
        if bundle_version == "0.4.0":
            from collective_phase_control_fabric.generation_v4 import GenerationStoreV4
            from collective_phase_control_fabric.workspace_v4 import doctor_v4

            generation_errors = GenerationStoreV4(bundle).verify_chain()
            doctor = doctor_v4(bundle)
            failure_prefix = "v0.4"
        else:
            from collective_phase_control_fabric.generation import GenerationStore
            from collective_phase_control_fabric.workspace_v3 import doctor_v3

            generation_errors = GenerationStore(bundle).verify_chain()
            doctor = doctor_v3(bundle)
            failure_prefix = "v0.3"
        doctor_errors = list(doctor.get("errors", []))
        if doctor.get("command_status") != "ok":
            errors.append(f"{failure_prefix}_strict_doctor_failed")
        if generation_errors:
            errors.append(f"{failure_prefix}_generation_chain_failed")
    authenticity_status = "unknown"
    root_attestation = bundle / "root-attestation.json"
    authenticity_reasons: list[str] = []
    if root_attestation.is_file() and trust_policy is not None:
        from collective_phase_control_fabric.canonical import digest_v3_json, load_json_strict
        from collective_phase_control_fabric.trust_v4 import verify_statement

        statement = load_json_strict(root_attestation)
        trust = load_json_strict(trust_policy)
        if isinstance(statement, dict) and isinstance(trust, dict):
            protected = statement.get("protected", {})
            checked = verify_statement(
                statement,
                trust,
                authoritative_time=str(protected.get("signed_at"))
                if isinstance(protected, dict)
                else "",
                expected_schema_ref="bundle-root-attestation@0.4.0",
                expected_role="bundle_signer",
            )
            payload = statement.get("payload")
            manifest_digest = digest_v3_json(manifest_value)
            if (
                not isinstance(payload, dict)
                or payload.get("bundle_manifest_digest") != manifest_digest
            ):
                authenticity_reasons.append("bundle_manifest_digest_mismatch")
            authenticity_reasons.extend(str(item) for item in checked.get("reasons", []))
            authenticity_status = "verified" if not authenticity_reasons else "invalid"
        else:
            authenticity_reasons.append("bundle_root_or_trust_not_object")
            authenticity_status = "invalid"
    return {
        "command_status": "ok" if not errors else "failed",
        "valid": not errors,
        "errors": errors,
        "object_count": len(manifest_value["objects"]),
        "bundle_schema_version": manifest_value.get("bundle_schema_version"),
        "generation_chain_errors": generation_errors,
        "doctor_errors": doctor_errors,
        "content_status": "content_consistent" if not errors else "content_invalid",
        "authenticity_status": authenticity_status,
        "authenticity_reasons": authenticity_reasons,
        "external_effect": False,
    }
