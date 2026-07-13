# SPDX-License-Identifier: Apache-2.0
"""Versioned JSON Schema discovery and validation."""

from __future__ import annotations

import json
from collections.abc import Mapping
from importlib.resources import files
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from collective_phase_control_fabric.types import JsonObject, JsonValue

SCHEMA_VERSION = "v0.6.0"
LEGACY_SCHEMA_VERSION = "v0.1.0"
SCHEMA_VERSIONS = ("v0.1.0", "v0.2.0", "v0.3.0", "v0.4.0", "v0.5.0", "v0.6.0")


def schema_root() -> Path:
    """Return the packaged schema directory."""

    packaged = Path(str(files("collective_phase_control_fabric") / "data" / "schemas"))
    if packaged.is_dir():
        return packaged
    return Path(__file__).resolve().parents[2] / "schemas"


def schema_names(version: str = LEGACY_SCHEMA_VERSION) -> list[str]:
    """List stable schema names."""

    return sorted(
        path.name.removesuffix(".schema.json")
        for path in (schema_root() / _normalized_version(version)).glob("*.schema.json")
    )


def _normalized_version(version: str) -> str:
    normalized = version if version.startswith("v") else f"v{version}"
    if normalized not in SCHEMA_VERSIONS:
        raise KeyError(f"unsupported schema version: {version}")
    return normalized


def load_schema(name: str, version: str = LEGACY_SCHEMA_VERSION) -> JsonObject:
    """Load a named schema from package data."""

    path = schema_root() / _normalized_version(version) / f"{name}.schema.json"
    if not path.is_file():
        raise KeyError(f"unknown schema: {name}")
    return cast(JsonObject, json.loads(path.read_text(encoding="utf-8")))


def validation_errors(
    name: str, value: JsonValue, version: str = LEGACY_SCHEMA_VERSION
) -> list[JsonObject]:
    """Return stable validation errors instead of promoting malformed input."""

    normalized = _normalized_version(version)
    registry: Registry[bool | Mapping[str, Any]] = Registry()
    for path in (schema_root() / normalized).glob("*.schema.json"):
        candidate = cast(JsonObject, json.loads(path.read_text(encoding="utf-8")))
        identifier = candidate.get("$id")
        if isinstance(identifier, str):
            registry = registry.with_resource(identifier, Resource.from_contents(candidate))
    validator = Draft202012Validator(
        load_schema(name, normalized), format_checker=FormatChecker(), registry=registry
    )
    return [
        {
            "message": error.message,
            "json_pointer": "/" + "/".join(str(part) for part in error.absolute_path),
            "schema_pointer": "/" + "/".join(str(part) for part in error.absolute_schema_path),
        }
        for error in sorted(validator.iter_errors(value), key=lambda item: list(item.absolute_path))
    ]
