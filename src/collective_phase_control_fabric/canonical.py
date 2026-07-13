# SPDX-License-Identifier: Apache-2.0
"""Canonical JSON and content digests."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import cast

from collective_phase_control_fabric.types import JsonValue


class DuplicateKeyError(ValueError):
    """Raised when a JSON object repeats a member name."""


def _unique_object(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _v3_value(value: JsonValue) -> JsonValue:
    """Validate the exact CPCF v0.3 canonical JSON profile.

    CPCF uses the RFC 8785 member ordering and UTF-8 representation but deliberately excludes
    floating-point values. Quantities are integers or rational strings, avoiding cross-runtime
    number serialization and precision ambiguity.
    """

    if isinstance(value, float):
        raise ValueError("v0.3 canonical JSON forbids floating-point values")
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > 9_007_199_254_740_991:
            raise ValueError("v0.3 canonical JSON integer exceeds the I-JSON exact range")
        return value
    if isinstance(value, list):
        return [_v3_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _v3_value(item) for key, item in value.items()}
    return value


def canonical_v3_bytes(value: JsonValue) -> bytes:
    """Encode the exact, float-free CPCF v0.3 RFC 8785 profile."""

    checked = _v3_value(value)

    def encode(item: JsonValue) -> str:
        if item is None:
            return "null"
        if item is True:
            return "true"
        if item is False:
            return "false"
        if isinstance(item, int):
            return str(item)
        if isinstance(item, str):
            return json.dumps(item, ensure_ascii=False, allow_nan=False)
        if isinstance(item, list):
            return "[" + ",".join(encode(child) for child in item) + "]"
        if isinstance(item, dict):
            # RFC 8785 sorts object names as arrays of UTF-16 code units.
            keys = sorted(item, key=lambda key: key.encode("utf-16-be", errors="surrogatepass"))
            return "{" + ",".join(f"{encode(key)}:{encode(item[key])}" for key in keys) + "}"
        raise ValueError("unsupported v0.3 canonical JSON value")

    return encode(checked).encode("utf-8")


def loads_json_strict(data: bytes | str) -> JsonValue:
    """Parse UTF-8 JSON while rejecting duplicate keys and non-exact v0.3 values."""

    text = data.decode("utf-8") if isinstance(data, bytes) else data
    value = cast(JsonValue, json.loads(text, object_pairs_hook=_unique_object))
    return _v3_value(value)


def canonical_bytes(value: JsonValue) -> bytes:
    """Encode deterministic UTF-8 JSON with sorted keys and no non-finite numbers."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def digest_bytes(data: bytes) -> str:
    """Return a tagged SHA-256 digest."""

    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def digest_json(value: JsonValue) -> str:
    """Return the digest of canonical JSON."""

    return digest_bytes(canonical_bytes(value))


def digest_v3_json(value: JsonValue) -> str:
    """Return a digest under the CPCF v0.3 RFC 8785 profile."""

    return digest_bytes(canonical_v3_bytes(value))


def load_json(path: Path) -> JsonValue:
    """Load UTF-8 JSON from a file."""

    with path.open("r", encoding="utf-8") as stream:
        return cast(JsonValue, json.load(stream))


def load_json_strict(path: Path) -> JsonValue:
    """Load a v0.3 JSON document with duplicate-key and exact-value checks."""

    return loads_json_strict(path.read_bytes())


def write_canonical(path: Path, value: JsonValue) -> None:
    """Atomically write canonical JSON followed by one newline.

    The staging file is created in the destination directory, flushed, and replaced.  A
    best-effort directory fsync closes the rename durability gap on platforms that support it.
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    data = canonical_bytes(value) + b"\n"
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        try:
            directory = os.open(path.parent, os.O_RDONLY)
        except (AttributeError, OSError):
            directory = None
        if directory is not None:
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        with suppress(FileNotFoundError):
            os.unlink(temporary)
