# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from collective_phase_control_fabric import canonical
from collective_phase_control_fabric.canonical import load_json, write_canonical
from collective_phase_control_fabric.cas import ContentAddressedStore
from collective_phase_control_fabric.locking import WorkspaceLock


def test_atomic_replace_failure_preserves_previous_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "state.json"
    write_canonical(path, {"generation": 1})

    def fail_replace(source: object, destination: object) -> None:
        del source, destination
        raise OSError("simulated replacement failure")

    monkeypatch.setattr(canonical.os, "replace", fail_replace)
    with pytest.raises(OSError, match="simulated"):
        write_canonical(path, {"generation": 2})
    assert load_json(path) == {"generation": 1}
    assert not list(tmp_path.glob(".state.json.*"))


def test_workspace_lock_serializes_threads(tmp_path: Path) -> None:
    active = 0
    maximum_active = 0
    guard = threading.Lock()
    errors: list[BaseException] = []

    def critical_section() -> None:
        nonlocal active, maximum_active
        try:
            with WorkspaceLock(tmp_path):
                with guard:
                    active += 1
                    maximum_active = max(maximum_active, active)
                time.sleep(0.01)
                with guard:
                    active -= 1
        except BaseException as error:
            errors.append(error)

    threads = [threading.Thread(target=critical_section) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert maximum_active == 1
    assert errors == []


def test_concurrent_identical_cas_puts_are_idempotent(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path / "cas")
    results: list[str] = []
    errors: list[BaseException] = []

    def put() -> None:
        try:
            results.append(store.put(b"same immutable bytes").digest)
        except BaseException as error:
            errors.append(error)

    threads = [threading.Thread(target=put) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
    assert errors == []
    assert len(results) == 6
    assert len(set(results)) == 1
    assert store.verify(results[0]) is True
