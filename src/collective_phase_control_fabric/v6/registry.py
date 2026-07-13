# SPDX-License-Identifier: Apache-2.0
"""One-to-one v0.6 kind, runtime model, and immutable schema registry."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, cast

from pydantic import ValidationError

from collective_phase_control_fabric.v6.canonical import (
    canonical_bytes,
    digest_bytes,
    loads_bounded,
)
from collective_phase_control_fabric.v6.models import DOCUMENT_MODELS, Document, DocumentType


class DocumentValidationError(ValueError):
    """Stable validation failure carrying a machine-readable code."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def _close_schema(value: Any) -> Any:
    if isinstance(value, list):
        return [_close_schema(item) for item in value]
    if not isinstance(value, dict):
        return value
    result = {key: _close_schema(item) for key, item in value.items()}
    if "properties" in result:
        result["additionalProperties"] = False
        result["unevaluatedProperties"] = False
    return result


def schema_for_kind(kind: str) -> dict[str, Any]:
    model = DOCUMENT_MODELS.get(kind)
    if model is None:
        raise DocumentValidationError("unknown_document_kind", kind)
    schema = _close_schema(deepcopy(model.model_json_schema(mode="validation")))
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = f"https://schemas.cpcf.dev/v0.6.0/{kind}.schema.json"
    return cast(dict[str, Any], schema)


def schema_digest(kind: str) -> str:
    return digest_bytes(canonical_bytes(schema_for_kind(kind)))


def parse_document(value: dict[str, Any]) -> DocumentType:
    if value.get("api_version") != "cpcf.io/v0.6":
        raise DocumentValidationError("unsupported_document_version")
    kind = value.get("kind")
    if not isinstance(kind, str):
        raise DocumentValidationError("document_kind_required")
    model = DOCUMENT_MODELS.get(kind)
    if model is None:
        raise DocumentValidationError("unknown_document_kind", kind)
    try:
        return cast(DocumentType, model.model_validate_json(canonical_bytes(value), strict=True))
    except ValidationError as error:
        raise DocumentValidationError("document_schema_invalid", str(error)) from error


def parse_document_bytes(data: bytes) -> DocumentType:
    return parse_document(loads_bounded(data))


def document_digest(document: Document) -> str:
    value = document.model_dump(mode="json", exclude_none=True)
    return digest_bytes(canonical_bytes(value))


def registry_manifest() -> dict[str, Any]:
    return {
        "api_version": "cpcf.io/v0.6",
        "canonicalization_profile": "RFC8785-CPCF-FLOAT-FREE-2",
        "schemas": [
            {"kind": kind, "digest": schema_digest(kind)} for kind in sorted(DOCUMENT_MODELS)
        ],
    }


def write_schemas(directory: Path) -> None:
    """Mechanically export the runtime models; checked-in output is tested for equality."""

    from collective_phase_control_fabric.canonical import write_canonical

    directory.mkdir(parents=True, exist_ok=True)
    for kind in sorted(DOCUMENT_MODELS):
        write_canonical(directory / f"{kind}.schema.json", cast(Any, schema_for_kind(kind)))
    write_canonical(directory / "registry-manifest.json", cast(Any, registry_manifest()))
