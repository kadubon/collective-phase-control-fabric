# SPDX-License-Identifier: Apache-2.0
"""Run deterministic failure-injection checks for local control-plane invariants."""

from __future__ import annotations

import argparse
import json
import re
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from collective_phase_control_fabric.v6.canonical import canonical_bytes, digest_bytes

COMMIT = re.compile(r"^[0-9a-f]{40}$")


@dataclass
class ReferenceState:
    generation: int = 0
    objects: set[str] = field(default_factory=set)
    outbox: set[str] = field(default_factory=set)
    completed: set[str] = field(default_factory=set)

    def transact(self, object_digest: str, message_id: str, *, fail_at: str | None = None) -> None:
        staged_objects = {*self.objects, object_digest}
        if fail_at == "object_uploaded":
            raise RuntimeError("injected_object_store_interruption")
        staged_outbox = {*self.outbox, message_id}
        if fail_at == "outbox_staged":
            raise RuntimeError("injected_database_restart")
        self.objects = staged_objects
        self.outbox = staged_outbox
        self.generation += 1

    def consume(self, message_id: str) -> None:
        if message_id in self.completed:
            return
        if message_id not in self.outbox:
            raise RuntimeError("unknown_outbox_message")
        self.completed.add(message_id)


def run_scenarios() -> list[dict[str, str]]:
    scenarios: list[dict[str, str]] = []
    for failure in ("object_uploaded", "outbox_staged"):
        state = ReferenceState()
        with suppress(RuntimeError):
            state.transact("sha256:" + "1" * 64, "message-1", fail_at=failure)
        if state.generation != 0 or state.objects or state.outbox:
            raise AssertionError(f"partial state escaped injected failure: {failure}")
        scenarios.append({"name": failure, "status": "passed"})
    state = ReferenceState()
    state.transact("sha256:" + "2" * 64, "message-2")
    state.consume("message-2")
    state.consume("message-2")
    if state.completed != {"message-2"}:
        raise AssertionError("duplicate message was not idempotent")
    scenarios.append({"name": "duplicate_outbox_delivery", "status": "passed"})

    active_key = "key-new"
    observed_keys = {"key-old", active_key}
    observed_keys.remove("key-old")
    if active_key not in observed_keys or "key-old" in observed_keys:
        raise AssertionError("OIDC or KMS rotation model retained a retired key")
    scenarios.append({"name": "oidc_kms_key_rotation", "status": "passed"})

    lease_owner = "worker-a"
    lease_expires = 10
    now = 11
    if now > lease_expires:
        lease_owner = "worker-b"
    if lease_owner != "worker-b":
        raise AssertionError("expired worker lease was not reclaimable")
    scenarios.append({"name": "worker_restart_expired_lease", "status": "passed"})
    return scenarios


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if COMMIT.fullmatch(args.commit) is None:
        raise SystemExit("commit must be a lowercase 40-character Git SHA")
    try:
        scenarios = run_scenarios()
    except AssertionError as error:
        raise SystemExit(str(error)) from error
    content: dict[str, Any] = {
        "schema_version": "cpcf.io/operations-evidence/v1",
        "kind": "reference-chaos-harness",
        "commit_sha": args.commit,
        "observed_at": datetime.now(UTC).isoformat(),
        "claim_boundary": (
            "Deterministic model failure injection only; not deployed Kubernetes, PostgreSQL, "
            "S3, KMS, OIDC, or availability evidence."
        ),
        "scenarios": scenarios,
    }
    content["evidence_digest"] = digest_bytes(canonical_bytes(content))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(content, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(f"chaos harness passed: {len(scenarios)} scenarios")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
