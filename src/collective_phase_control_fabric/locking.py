# SPDX-License-Identifier: Apache-2.0
"""Cross-platform advisory workspace locking."""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from types import TracebackType

_INITIALIZATION_LOCK = threading.Lock()


class WorkspaceLock:
    """Hold an exclusive lock on one byte of a workspace-owned lock file."""

    def __init__(self, workspace: Path, *, timeout_seconds: float = 10.0) -> None:
        self.path = workspace / ".cpcf" / "workspace.lock"
        self._stream: object | None = None
        self.timeout_seconds = max(0.0, timeout_seconds)

    def __enter__(self) -> WorkspaceLock:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with _INITIALIZATION_LOCK:
            try:
                with self.path.open("xb") as initializer:
                    initializer.write(b"0")
                    initializer.flush()
                    os.fsync(initializer.fileno())
            except FileExistsError:
                pass
            for _ in range(20):
                if self.path.stat().st_size >= 1:
                    break
                time.sleep(0.005)
            else:
                raise RuntimeError("workspace lock file initialization did not complete")
        stream = self.path.open("r+b")
        stream.seek(0)
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            try:
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    exclusive = int(fcntl.__dict__["LOCK_EX"])
                    nonblocking = int(fcntl.__dict__["LOCK_NB"])
                    fcntl.flock(stream.fileno(), exclusive | nonblocking)  # type: ignore[attr-defined]
                break
            except OSError as error:
                if time.monotonic() >= deadline:
                    stream.close()
                    raise TimeoutError("workspace lock acquisition timed out") from error
                time.sleep(0.01)
        self._stream = stream
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        stream = self._stream
        if stream is None:
            return
        if os.name == "nt":
            import msvcrt

            stream.seek(0)  # type: ignore[attr-defined]
            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]
        else:
            import fcntl

            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)  # type: ignore[attr-defined]
        stream.close()  # type: ignore[attr-defined]
        self._stream = None
