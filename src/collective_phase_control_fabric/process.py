# SPDX-License-Identifier: Apache-2.0
"""Bounded subprocess execution for explicitly registered operations."""

from __future__ import annotations

import hashlib
import os
import shutil
import signal
import subprocess  # nosec B404
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

from collective_phase_control_fabric.types import JsonObject

ENV_ALLOWLIST = frozenset(
    {
        "COMSPEC",
        "HOME",
        "LANG",
        "LC_ALL",
        "LOCALAPPDATA",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "WINDIR",
    }
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _executable_digest(path: str) -> str | None:
    executable = Path(path)
    if not executable.is_file():
        return None
    digest = hashlib.sha256()
    try:
        with executable.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError:
        return None
    return f"sha256:{digest.hexdigest()}"


def _windows_job(process: subprocess.Popen[bytes]) -> tuple[object, int] | None:
    """Put a Windows process in a kill-on-close Job Object."""

    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes

    class IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class BasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class ExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BasicLimitInformation),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.__dict__["WinDLL"]("kernel32", use_last_error=True)
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        return None
    information = ExtendedLimitInformation()
    information.BasicLimitInformation.LimitFlags = 0x00002000
    if not kernel32.SetInformationJobObject(
        job, 9, ctypes.byref(information), ctypes.sizeof(information)
    ) or not kernel32.AssignProcessToJobObject(job, wintypes.HANDLE(process._handle)):  # type: ignore[attr-defined]
        kernel32.CloseHandle(job)
        return None
    return kernel32, int(job)


def run_process(
    argv: list[str],
    cwd: Path,
    boundary: Path,
    *,
    timeout_seconds: float = 30.0,
    stdin_bytes: bytes = b"",
    stdin_limit: int = 1_048_576,
    stdout_limit: int = 1_048_576,
    stderr_limit: int = 1_048_576,
    environment_allowlist: frozenset[str] = ENV_ALLOWLIST,
) -> JsonObject:
    """Run one exact argv while bounding retained bytes and draining both pipes.

    Reader threads never retain more than each configured limit.  Bytes beyond the limit are
    discarded after contributing to a full-stream digest and byte count, preventing child-process
    deadlock without turning a declared capture limit into an unbounded allocation.
    """

    if not argv or not all(isinstance(item, str) and item for item in argv):
        raise ValueError("argv must contain non-empty strings")
    if len(stdin_bytes) > stdin_limit:
        raise ValueError("stdin exceeds the declared byte limit")
    resolved_cwd = cwd.resolve()
    resolved_boundary = boundary.resolve()
    if resolved_cwd != resolved_boundary and resolved_boundary not in resolved_cwd.parents:
        raise ValueError("cwd is outside the allowed path boundary")
    executable = shutil.which(argv[0])
    if executable is None:
        raise FileNotFoundError(f"executable not found: {argv[0]}")
    environment = {key: value for key, value in os.environ.items() if key in environment_allowlist}
    creationflags = 0
    start_new_session = os.name != "nt"
    if os.name == "nt":
        creationflags = int(subprocess.__dict__["CREATE_NEW_PROCESS_GROUP"])
    started_at = _utc_now()
    start = time.monotonic()
    # The executable and argv are canonical inputs, and shell execution is explicitly disabled.
    process = subprocess.Popen(  # nosec B603
        argv,
        cwd=resolved_cwd,
        env=environment,
        shell=False,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=creationflags,
        start_new_session=start_new_session,
    )
    windows_job = _windows_job(process)
    timed_out = False
    captured: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    totals = {"stdout": 0, "stderr": 0}
    hashes = {"stdout": hashlib.sha256(), "stderr": hashlib.sha256()}

    def drain(name: str, stream: object, limit: int) -> None:
        while True:
            block = stream.read(65_536)  # type: ignore[attr-defined]
            if not block:
                break
            totals[name] += len(block)
            hashes[name].update(block)
            remaining = limit - len(captured[name])
            if remaining > 0:
                captured[name].extend(block[:remaining])

    if process.stdout is None or process.stderr is None or process.stdin is None:
        process.kill()
        raise RuntimeError("subprocess pipes were not created")
    readers = [
        threading.Thread(target=drain, args=("stdout", process.stdout, stdout_limit), daemon=True),
        threading.Thread(target=drain, args=("stderr", process.stderr, stderr_limit), daemon=True),
    ]
    for reader in readers:
        reader.start()
    try:
        try:
            process.stdin.write(stdin_bytes)
            process.stdin.flush()
        except BrokenPipeError:
            pass
        finally:
            process.stdin.close()
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        if os.name == "nt":
            if windows_job is not None:
                kernel32, job = windows_job
                kernel32.TerminateJobObject(job, 1)  # type: ignore[attr-defined]
            else:
                process.kill()
        else:
            try:
                kill_group = getattr(os, "killpg", None)
                signal_kill = getattr(signal, "SIGKILL", signal.SIGTERM)
                if kill_group is None:
                    process.kill()
                else:
                    kill_group(process.pid, signal_kill)
            except OSError:
                process.kill()
        process.wait()
    cleanup = "complete" if os.name != "nt" or windows_job is not None else "best_effort"
    if windows_job is not None:
        kernel32, job = windows_job
        kernel32.CloseHandle(job)  # type: ignore[attr-defined]
    for reader in readers:
        reader.join(timeout=5.0)
    drain_status = "complete" if all(not reader.is_alive() for reader in readers) else "incomplete"
    if drain_status == "incomplete":
        cleanup = "incomplete"
        process.stdout.close()
        process.stderr.close()
    duration = time.monotonic() - start
    bounded_stdout = bytes(captured["stdout"])
    bounded_stderr = bytes(captured["stderr"])
    stdout_truncated = totals["stdout"] > stdout_limit
    stderr_truncated = totals["stderr"] > stderr_limit
    try:
        stdout_text = bounded_stdout.decode("utf-8")
        stdout_utf8 = True
    except UnicodeDecodeError:
        stdout_text = bounded_stdout.decode("utf-8", errors="replace")
        stdout_utf8 = False
    try:
        stderr_text = bounded_stderr.decode("utf-8")
        stderr_utf8 = True
    except UnicodeDecodeError:
        stderr_text = bounded_stderr.decode("utf-8", errors="replace")
        stderr_utf8 = False
    return {
        "argv": argv,
        "shell": False,
        "cwd": str(resolved_cwd),
        "environment_keys": sorted(environment),
        "started_at": started_at,
        "finished_at": _utc_now(),
        "duration_seconds": f"{duration:.6f}",
        "exit_code": process.returncode,
        "timed_out": timed_out,
        "timeout_seconds": str(timeout_seconds),
        "stdout_raw_hex": bounded_stdout.hex(),
        "stderr_raw_hex": bounded_stderr.hex(),
        "stdout_utf8": stdout_text,
        "stderr_utf8": stderr_text,
        "stdout_utf8_valid": stdout_utf8,
        "stderr_utf8_valid": stderr_utf8,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
        "stdin_byte_count": len(stdin_bytes),
        "stdin_byte_limit": stdin_limit,
        "stdout_byte_count_captured": len(bounded_stdout),
        "stderr_byte_count_captured": len(bounded_stderr),
        "stdout_byte_count_total": totals["stdout"],
        "stderr_byte_count_total": totals["stderr"],
        "stdout_full_digest": f"sha256:{hashes['stdout'].hexdigest()}",
        "stderr_full_digest": f"sha256:{hashes['stderr'].hexdigest()}",
        "maximum_retained_output_bytes": stdout_limit + stderr_limit,
        "executable_path": str(Path(executable).resolve()),
        "executable_digest": _executable_digest(executable),
        "process_group_cleanup": cleanup,
        "drain_status": drain_status,
        "network_sandboxed": False,
    }
