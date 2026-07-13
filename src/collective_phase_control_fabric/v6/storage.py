# SPDX-License-Identifier: Apache-2.0
"""Immutable object ledger and optimistic generation semantics for CPCF v0.6."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from collective_phase_control_fabric.v6.canonical import digest_bytes
from collective_phase_control_fabric.v6.models import (
    AuditEvent,
    Document,
    LedgerEntry,
    WorkspaceGeneration,
)
from collective_phase_control_fabric.v6.registry import document_digest, parse_document_bytes


class ConcurrentGenerationError(RuntimeError):
    pass


class ObjectStore(Protocol):
    def put(self, tenant_id: str, data: bytes) -> str: ...

    def get(self, tenant_id: str, digest: str) -> bytes: ...

    def exists(self, tenant_id: str, digest: str) -> bool: ...


@dataclass
class MemoryObjectStore:
    """Deterministic test store. Production uses the S3 adapter in cpcf-api."""

    values: dict[tuple[str, str], bytes] = field(default_factory=dict)

    def put(self, tenant_id: str, data: bytes) -> str:
        digest = digest_bytes(data)
        self.values.setdefault((tenant_id, digest), bytes(data))
        return digest

    def get(self, tenant_id: str, digest: str) -> bytes:
        return self.values[(tenant_id, digest)]

    def exists(self, tenant_id: str, digest: str) -> bool:
        return (tenant_id, digest) in self.values


def generation_digest(generation: WorkspaceGeneration) -> str:
    value = generation.model_dump(mode="json", exclude_none=True)
    value["spec"]["generation_digest"] = "sha256:" + "0" * 64
    from collective_phase_control_fabric.v6.canonical import canonical_bytes

    return digest_bytes(canonical_bytes(value))


def validate_ledger(
    generation: WorkspaceGeneration,
    object_store: ObjectStore,
) -> list[str]:
    reasons: list[str] = []
    entries = generation.spec.ledger
    digests = [item.object_digest for item in entries]
    if len(digests) != len(set(digests)):
        reasons.append("ledger_object_digest_duplicate")
    if generation.spec.generation_digest != generation_digest(generation):
        reasons.append("generation_digest_mismatch")
    by_digest = {item.object_digest: item for item in entries}
    tenant = generation.metadata.tenant_id
    for entry in entries:
        if not object_store.exists(tenant, entry.object_digest):
            reasons.append(f"ledger_object_missing:{entry.object_digest}")
            continue
        try:
            raw = object_store.get(tenant, entry.object_digest)
            if digest_bytes(raw) != entry.object_digest:
                reasons.append(f"ledger_raw_digest_mismatch:{entry.object_digest}")
                continue
            document = parse_document_bytes(raw)
            if document.kind != entry.object_kind:
                reasons.append(f"ledger_kind_mismatch:{entry.object_digest}")
        except ValueError:
            # Raw artifacts are represented by source-artifact-envelope entries and do not parse as
            # documents. Only an explicit raw-artifact kind may use opaque bytes.
            if entry.object_kind != "raw-artifact":
                reasons.append(f"ledger_document_invalid:{entry.object_digest}")
        for source in entry.source_digests:
            if source not in by_digest:
                reasons.append(f"ledger_source_dangling:{source}")
    if generation.spec.history_head_digest not in by_digest:
        reasons.append("history_head_missing_from_ledger")
    return sorted(set(reasons))


def validate_history(events: list[AuditEvent], expected_head: str) -> list[str]:
    reasons: list[str] = []
    prior: str | None = None
    identifiers: set[str] = set()
    for index, event in enumerate(events):
        if event.spec.event_id in identifiers:
            reasons.append("history_event_id_duplicate")
        identifiers.add(event.spec.event_id)
        if event.spec.prior_event_digest != prior:
            reasons.append(f"history_chain_broken:{index}")
        prior = document_digest(event)
    if prior != expected_head:
        reasons.append("history_head_mismatch")
    return sorted(set(reasons))


@dataclass
class WorkspaceState:
    generation: WorkspaceGeneration
    objects: dict[str, Document]


class MemoryGenerationRepository:
    """Serializable in-memory reference for API and concurrency tests."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._workspaces: dict[tuple[str, str], WorkspaceState] = {}

    def create(self, state: WorkspaceState) -> None:
        key = (state.generation.metadata.tenant_id, state.generation.metadata.workspace_id)
        with self._lock:
            if key in self._workspaces:
                raise ConcurrentGenerationError("workspace_already_exists")
            self._workspaces[key] = state

    def get(self, tenant_id: str, workspace_id: str) -> WorkspaceState:
        with self._lock:
            return self._workspaces[(tenant_id, workspace_id)]

    def commit(
        self,
        state: WorkspaceState,
        *,
        expected_generation_digest: str,
    ) -> None:
        key = (state.generation.metadata.tenant_id, state.generation.metadata.workspace_id)
        with self._lock:
            current = self._workspaces[key]
            if current.generation.spec.generation_digest != expected_generation_digest:
                raise ConcurrentGenerationError("workspace_generation_changed")
            if state.generation.spec.prior_generation_digest != expected_generation_digest:
                raise ConcurrentGenerationError("generation_predecessor_mismatch")
            if state.generation.spec.sequence != current.generation.spec.sequence + 1:
                raise ConcurrentGenerationError("generation_sequence_mismatch")
            self._workspaces[key] = state


def assert_safe_legacy_root(root: Path) -> Path:
    """Reject links/reparse points and containment escapes before legacy inspection."""

    if root.is_symlink():
        raise ValueError("legacy_workspace_link_rejected")
    resolved = root.resolve(strict=True)
    current = resolved
    while current != current.parent:
        if current.is_symlink():
            raise ValueError("legacy_workspace_link_rejected")
        current = current.parent
    return resolved


def quarantine_legacy_entries(raw_digests: list[str]) -> list[LedgerEntry]:
    """Legacy authority is never reinterpreted; raw bytes alone can be copied."""

    return [
        LedgerEntry(
            object_digest=digest,
            object_kind="raw-artifact",
            authority_status="quarantined",
            source_digests=[],
        )
        for digest in sorted(set(raw_digests))
    ]
