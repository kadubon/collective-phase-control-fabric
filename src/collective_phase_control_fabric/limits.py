# SPDX-License-Identifier: Apache-2.0
"""Non-overridable input and analysis ceilings for native CPCF documents."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from collective_phase_control_fabric.canonical import loads_json_strict
from collective_phase_control_fabric.types import JsonValue

MAX_RAW_BYTES = 64 * 1024 * 1024
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_OBJECT_MEMBERS = 10_000
MAX_ARRAY_ITEMS = 100_000
MAX_GRAPH_STATES = 10_000
MAX_GRAPH_TRANSFORMATIONS = 10_000
MAX_ACTIONS = 4_096
MAX_ELIGIBLE_ACTIONS = 64
MAX_PERTURBATIONS = 256
MAX_RATIONAL_BITS = 4_096
MAX_ANALYSIS_OPERATIONS = 10_000_000
DEFAULT_SOLVER_SECONDS = 30
DEFAULT_PROCESS_SECONDS = 30
HARD_PROCESS_SECONDS = 300
DEFAULT_CAPTURE_BYTES = 1 * 1024 * 1024
HARD_CAPTURE_BYTES = 4 * 1024 * 1024


class LimitExceeded(ValueError):
    """Raised before an input can trigger unbounded parsing or analysis."""

    def __init__(self, code: str, *, observed: int, maximum: int) -> None:
        super().__init__(f"{code}: observed={observed}, maximum={maximum}")
        self.code = code
        self.observed = observed
        self.maximum = maximum


@dataclass(frozen=True)
class JsonShape:
    """Measured recursive shape of a parsed document."""

    depth: int
    maximum_object_members: int
    maximum_array_items: int


def _lexical_depth(data: bytes) -> int:
    """Measure container nesting without constructing Python containers."""

    depth = 0
    maximum = 0
    quoted = False
    escaped = False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                quoted = False
            continue
        if byte == 0x22:
            quoted = True
        elif byte in (0x7B, 0x5B):
            depth += 1
            maximum = max(maximum, depth)
            if maximum > MAX_JSON_DEPTH:
                raise LimitExceeded(
                    "maximum_json_depth_exceeded", observed=maximum, maximum=MAX_JSON_DEPTH
                )
        elif byte in (0x7D, 0x5D):
            depth -= 1
            if depth < 0:
                raise ValueError("malformed JSON container nesting")
    if quoted or depth != 0:
        # json.loads supplies the final syntax diagnostic; this prevents an incomplete deep input.
        raise ValueError("malformed or incomplete JSON input")
    return maximum


def _shape(value: JsonValue, depth: int = 1) -> JsonShape:
    maximum_depth = depth
    object_members = len(value) if isinstance(value, dict) else 0
    array_items = len(value) if isinstance(value, list) else 0
    children = (
        value.values() if isinstance(value, dict) else value if isinstance(value, list) else []
    )
    for child in children:
        measured = _shape(child, depth + 1)
        maximum_depth = max(maximum_depth, measured.depth)
        object_members = max(object_members, measured.maximum_object_members)
        array_items = max(array_items, measured.maximum_array_items)
    return JsonShape(maximum_depth, object_members, array_items)


def loads_json_bounded(data: bytes, *, maximum_bytes: int = MAX_JSON_BYTES) -> JsonValue:
    """Parse strict JSON only after byte and lexical-depth checks."""

    effective = min(maximum_bytes, MAX_JSON_BYTES)
    if len(data) > effective:
        raise LimitExceeded("maximum_json_bytes_exceeded", observed=len(data), maximum=effective)
    _lexical_depth(data)
    try:
        value = loads_json_strict(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid JSON: {error}") from error
    measured = _shape(value)
    if measured.depth > MAX_JSON_DEPTH:
        raise LimitExceeded(
            "maximum_json_depth_exceeded", observed=measured.depth, maximum=MAX_JSON_DEPTH
        )
    if measured.maximum_object_members > MAX_OBJECT_MEMBERS:
        raise LimitExceeded(
            "maximum_object_members_exceeded",
            observed=measured.maximum_object_members,
            maximum=MAX_OBJECT_MEMBERS,
        )
    if measured.maximum_array_items > MAX_ARRAY_ITEMS:
        raise LimitExceeded(
            "maximum_array_items_exceeded",
            observed=measured.maximum_array_items,
            maximum=MAX_ARRAY_ITEMS,
        )
    return value


def load_json_bounded(path: Path, *, maximum_bytes: int = MAX_JSON_BYTES) -> JsonValue:
    """Read at most one byte beyond the effective limit and parse strict JSON."""

    effective = min(maximum_bytes, MAX_JSON_BYTES)
    with path.open("rb") as stream:
        data = stream.read(effective + 1)
    if len(data) > effective:
        raise LimitExceeded("maximum_json_bytes_exceeded", observed=len(data), maximum=effective)
    return loads_json_bounded(data, maximum_bytes=effective)


def bounded_object(path: Path, *, maximum_bytes: int = MAX_JSON_BYTES) -> dict[str, JsonValue]:
    """Load one bounded JSON object."""

    value = load_json_bounded(path, maximum_bytes=maximum_bytes)
    if not isinstance(value, dict):
        raise ValueError("JSON document must be an object")
    return cast(dict[str, JsonValue], value)
