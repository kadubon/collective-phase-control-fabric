# SPDX-License-Identifier: Apache-2.0
"""Bounded strict parsing and canonical byte production for CPCF v0.6."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, BinaryIO, cast

from collective_phase_control_fabric.canonical import (  # gitleaks:allow -- identifiers only
    DuplicateKeyError,
    canonical_v3_bytes,
)

MAX_RAW_BYTES = 64 * 1024 * 1024
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_DEPTH = 64
MAX_OBJECT_MEMBERS = 10_000
MAX_ARRAY_ITEMS = 100_000


class InputLimitError(ValueError):
    """Raised before expensive parsing when a system ceiling is exceeded."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def read_limited(stream: BinaryIO, limit: int = MAX_RAW_BYTES) -> bytes:
    """Read at most limit bytes and reject one extra byte without unbounded buffering."""

    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = stream.read(min(64 * 1024, limit + 1 - size))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        size += len(chunk)
        if size > limit:
            raise InputLimitError("raw_input_too_large")


def read_path_limited(path: Path, limit: int = MAX_RAW_BYTES) -> bytes:
    with path.open("rb") as stream:
        return read_limited(stream, limit)


def _scan_nesting(data: bytes, max_depth: int) -> None:
    depth = 0
    in_string = False
    escaped = False
    for byte in data:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in (0x5B, 0x7B):
            depth += 1
            if depth > max_depth:
                raise InputLimitError("json_nesting_too_deep")
        elif byte in (0x5D, 0x7D):
            depth -= 1
            if depth < 0:
                raise ValueError("malformed_json_structure")
    if in_string or depth != 0:
        raise ValueError("malformed_json_structure")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len(pairs) > MAX_OBJECT_MEMBERS:
        raise InputLimitError("json_object_member_limit")
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _validate_tree(value: Any, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise InputLimitError("json_nesting_too_deep")
    if isinstance(value, float):
        raise ValueError("floating_point_values_are_forbidden")
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > 9_007_199_254_740_991:
            raise InputLimitError("json_integer_outside_i_json_range")
    elif isinstance(value, list):
        if len(value) > MAX_ARRAY_ITEMS:
            raise InputLimitError("json_array_item_limit")
        for item in value:
            _validate_tree(item, depth + 1)
    elif isinstance(value, dict):
        if len(value) > MAX_OBJECT_MEMBERS:
            raise InputLimitError("json_object_member_limit")
        for item in value.values():
            _validate_tree(item, depth + 1)
    elif value is not None and not isinstance(value, (bool, str)):
        raise ValueError("unsupported_json_value")


def loads_bounded(data: bytes, limit: int = MAX_JSON_BYTES) -> dict[str, Any]:
    """Parse a closed CPCF document after byte and lexical checks."""

    if len(data) > limit:
        raise InputLimitError("json_document_too_large")
    _scan_nesting(data, MAX_DEPTH)
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object)
    except UnicodeDecodeError as error:
        raise ValueError("json_not_utf8") from error
    _validate_tree(value)
    if not isinstance(value, dict):
        raise ValueError("top_level_json_object_required")
    return cast(dict[str, Any], value)


def canonical_bytes(value: dict[str, Any]) -> bytes:
    return canonical_v3_bytes(cast(Any, value))


def digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_document(value: dict[str, Any]) -> str:
    return digest_bytes(canonical_bytes(value))
