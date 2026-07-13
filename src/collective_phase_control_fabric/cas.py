# SPDX-License-Identifier: Apache-2.0
"""A rebuildable, content-addressed local artifact store."""

from __future__ import annotations

import hashlib
import os
import tempfile
import threading
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from string import hexdigits

from collective_phase_control_fabric.canonical import digest_bytes

_CAS_LOCKS: dict[str, threading.Lock] = {}
_CAS_LOCKS_GUARD = threading.Lock()


@dataclass(frozen=True)
class StoredArtifact:
    """A stored immutable blob reference."""

    digest: str
    path: Path
    size: int


class ContentAddressedStore:
    """Store raw bytes below a fixed root without changing source artifacts."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    def _path_for(self, digest: str) -> Path:
        algorithm, value = digest.split(":", maxsplit=1)
        if (
            algorithm != "sha256"
            or len(value) != 64
            or any(char not in hexdigits for char in value)
        ):
            raise ValueError("unsupported or malformed digest")
        # `value` is already restricted to 64 hexadecimal characters, so this lexical join cannot
        # contain a separator or traversal component. Avoid resolving a concurrently created path;
        # Windows Python 3.14 may observe transient filesystem state during that operation.
        return self.root / "sha256" / value[:2] / value[2:]

    @staticmethod
    def _matches_eventually(path: Path, data: bytes) -> bool:
        for _ in range(200):
            try:
                return path.read_bytes() == data
            except OSError:
                time.sleep(0.005)
        return False

    @staticmethod
    def _lock_for(path: Path) -> threading.Lock:
        key = str(path)
        with _CAS_LOCKS_GUARD:
            return _CAS_LOCKS.setdefault(key, threading.Lock())

    def put(self, data: bytes) -> StoredArtifact:
        """Persist bytes if absent and return their immutable reference."""

        digest = digest_bytes(data)
        path = self._path_for(digest)
        with self._lock_for(path):
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                if not self._matches_eventually(path, data):
                    raise RuntimeError("digest collision or corrupted CAS object")
            else:
                descriptor, temporary = tempfile.mkstemp(prefix=".cas-", dir=path.parent)
                try:
                    with os.fdopen(descriptor, "wb") as stream:
                        stream.write(data)
                        stream.flush()
                        os.fsync(stream.fileno())
                    try:
                        os.replace(temporary, path)
                    except OSError:
                        if not self._matches_eventually(path, data):
                            raise
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
        return StoredArtifact(digest=digest, path=path, size=len(data))

    def get(self, digest: str) -> bytes:
        """Read bytes and verify their digest."""

        data = self._path_for(digest).read_bytes()
        if digest_bytes(data) != digest:
            raise RuntimeError("CAS object failed digest verification")
        return data

    def get_limited(self, digest: str, maximum_bytes: int) -> bytes:
        """Read and verify at most a declared number of retained bytes."""

        path = self._path_for(digest)
        hasher = hashlib.sha256()
        retained = bytearray()
        total = 0
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(65_536), b""):
                total += len(block)
                if total > maximum_bytes:
                    raise ValueError("CAS object exceeds the declared byte limit")
                hasher.update(block)
                retained.extend(block)
        if f"sha256:{hasher.hexdigest()}" != digest:
            raise RuntimeError("CAS object failed digest verification")
        return bytes(retained)

    def verify(self, digest: str) -> bool:
        """Return whether an object exists and matches its digest."""

        try:
            path = self._path_for(digest)
            hasher = hashlib.sha256()
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(65_536), b""):
                    hasher.update(block)
            return f"sha256:{hasher.hexdigest()}" == digest
        except (OSError, RuntimeError, ValueError):
            return False
