# SPDX-License-Identifier: Apache-2.0
"""PostgreSQL unit-of-work and worker claim-path assurance without external effects."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from cpcf_api.app import ApiResponse
from cpcf_api.db import (
    AuditEventRow,
    GenerationMutation,
    GenerationRow,
    IdempotencyRow,
    LedgerRow,
    ObjectAdmission,
    ObjectRow,
    OutboxRow,
    PostgresBackend,
    QuarantineRow,
    WorkspaceRow,
    _validate_generation_mutation,
    assert_application_role,
    lock_workspace,
    make_engine,
    set_tenant,
)
from sqlalchemy.exc import IntegrityError

from collective_phase_control_fabric.v6.canonical import canonical_bytes
from collective_phase_control_fabric.v6.models import (
    AuditEvent,
    AuditEventSpec,
    LedgerEntry,
    WorkspaceGeneration,
    WorkspaceGenerationSpec,
)
from collective_phase_control_fabric.v6.registry import document_digest
from collective_phase_control_fabric.v6.storage import MemoryObjectStore, generation_digest
from tests.v6_helpers import NOW, metadata, trust_fixture


class AsyncContext:
    def __init__(self, value: object, error: BaseException | None = None) -> None:
        self.value = value
        self.error = error

    async def __aenter__(self) -> object:
        if self.error is not None:
            raise self.error
        return self.value

    async def __aexit__(self, *_: object) -> None:
        return None


class Sessions:
    def __init__(self, session: object, error: BaseException | None = None) -> None:
        self.session = session
        self.error = error

    def __call__(self) -> AsyncContext:
        return AsyncContext(self.session, self.error)

    def begin(self) -> AsyncContext:
        return AsyncContext(self.session, self.error)


class Result:
    def __init__(self, *, one: object = None, scalar: object = None) -> None:
        self.one = one
        self.scalar = scalar

    def one_or_none(self) -> object:
        return self.one

    def scalar_one(self) -> object:
        return self.scalar

    def scalar_one_or_none(self) -> object:
        return self.scalar


class ScalarRows:
    def __init__(self, values: list[object]) -> None:
        self.values = values

    def scalars(self) -> ScalarRows:
        return self

    def all(self) -> list[object]:
        return self.values


def response() -> ApiResponse:
    return ApiResponse(
        status="ok",
        code="test",
        effect_class="inspect",
        trace_id="1" * 32,
    )


def test_engine_tenant_setting_application_role_and_workspace_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValueError, match="psycopg async URL"):
        make_engine("sqlite:///local")
    engine = object()
    monkeypatch.setattr("cpcf_api.db.create_async_engine", lambda *args, **kwargs: engine)
    assert make_engine("postgresql+psycopg://user@host/database") is engine

    session = SimpleNamespace(execute=AsyncMock())
    asyncio.run(set_tenant(session, "tenant-a"))
    assert session.execute.await_count == 1

    async def role_case(posture: object, owned: int = 0) -> None:
        role_session = SimpleNamespace(
            execute=AsyncMock(side_effect=[Result(one=posture), Result(scalar=owned)])
        )
        await assert_application_role(role_session)

    asyncio.run(role_case(SimpleNamespace(rolsuper=False, rolbypassrls=False)))
    for posture in (
        None,
        SimpleNamespace(rolsuper=True, rolbypassrls=False),
        SimpleNamespace(rolsuper=False, rolbypassrls=True),
    ):
        with pytest.raises(RuntimeError, match="bypasses_rls"):
            asyncio.run(role_case(posture))
    with pytest.raises(RuntimeError, match="owns_tenant_tables"):
        asyncio.run(role_case(SimpleNamespace(rolsuper=False, rolbypassrls=False), owned=1))

    async def lock_case(row: object, expected: str = "generation") -> object:
        lock_session = SimpleNamespace(execute=AsyncMock(), get=AsyncMock(return_value=row))
        return await lock_workspace(lock_session, "tenant-a", "workspace-a", expected)

    valid = SimpleNamespace(current_generation_digest="generation")
    assert asyncio.run(lock_case(valid)) is valid
    with pytest.raises(KeyError, match="workspace_not_found"):
        asyncio.run(lock_case(None))
    with pytest.raises(RuntimeError, match="workspace_generation_changed"):
        asyncio.run(lock_case(valid, "other"))


def backend_with(session: object, error: BaseException | None = None) -> PostgresBackend:
    backend = PostgresBackend.__new__(PostgresBackend)
    backend.sessions = Sessions(session, error)  # type: ignore[assignment]
    return backend


def test_postgres_backend_startup_create_workspace_and_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("cpcf_api.db.assert_application_role", AsyncMock())
    startup_session = SimpleNamespace()
    asyncio.run(backend_with(startup_session).startup())

    session = SimpleNamespace(execute=AsyncMock(), add=Mock(), get=AsyncMock())
    backend = backend_with(session)
    created = asyncio.run(
        backend.create_workspace(
            "tenant-a",
            "workspace-a",
            "sha256:" + "1" * 64,
            "sha256:" + "2" * 64,
        )
    )
    assert created.workspace_id == "workspace-a" and created.sequence == 0
    assert session.add.call_args.args[0].tenant_id == "tenant-a"

    failure = IntegrityError("statement", {}, Exception("duplicate"))
    with pytest.raises(ValueError, match="workspace_already_exists"):
        asyncio.run(
            backend_with(session, failure).create_workspace(
                "tenant-a",
                "workspace-a",
                "sha256:" + "1" * 64,
                "sha256:" + "2" * 64,
            )
        )

    now = datetime.now(UTC)
    row = WorkspaceRow(
        tenant_id="tenant-a",
        workspace_id="workspace-a",
        current_generation_digest="sha256:" + "1" * 64,
        generation_sequence=2,
        root_spki_fingerprint="sha256:" + "1" * 64,
        genesis_envelope_fingerprint="sha256:" + "2" * 64,
        created_at=now,
    )
    session.get = AsyncMock(return_value=row)
    loaded = asyncio.run(backend.workspace("tenant-a", "workspace-a"))
    assert loaded.sequence == 2
    session.get = AsyncMock(return_value=None)
    with pytest.raises(ValueError, match="workspace_not_found"):
        asyncio.run(backend.workspace("tenant-a", "missing"))


def test_postgres_backend_outbox_job_and_idempotency_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("cpcf_api.db.secrets.token_hex", lambda _: "message-id")
    session = SimpleNamespace(execute=AsyncMock(), add=Mock(), get=AsyncMock())
    backend = backend_with(session)
    assert asyncio.run(backend.enqueue("tenant-a", "workspace-a", "analysis")) == "message-id"
    assert isinstance(session.add.call_args.args[0], OutboxRow)

    session.get = AsyncMock(return_value=None)
    assert asyncio.run(backend.job("tenant-a", "missing")) is None
    for completed, leased, status in (
        (datetime.now(UTC), None, "succeeded"),
        (None, datetime.now(UTC), "running"),
        (None, None, "queued"),
    ):
        session.get = AsyncMock(
            return_value=SimpleNamespace(
                completed_at=completed,
                leased_until=leased,
                workspace_id="workspace-a",
                topic="analysis",
            )
        )
        assert asyncio.run(backend.job("tenant-a", "message-id"))["status"] == status  # type: ignore[index]

    session.get = AsyncMock(return_value=None)
    assert asyncio.run(backend.idempotency_get("tenant-a", "key", "request")) is None
    expired = SimpleNamespace(expires_at=datetime.now(UTC) - timedelta(seconds=1))
    session.get = AsyncMock(return_value=expired)
    assert asyncio.run(backend.idempotency_get("tenant-a", "key", "request")) is None
    cached_response = response()
    from collective_phase_control_fabric.v6.canonical import canonical_bytes

    current = SimpleNamespace(
        expires_at=datetime.now(UTC) + timedelta(minutes=1),
        request_digest="request",
        response_body=canonical_bytes(cached_response.model_dump(mode="json")),
    )
    session.get = AsyncMock(return_value=current)
    assert asyncio.run(backend.idempotency_get("tenant-a", "key", "request")) == cached_response
    with pytest.raises(ValueError, match="idempotency_key_reused"):
        asyncio.run(backend.idempotency_get("tenant-a", "key", "different"))

    session.get = AsyncMock(return_value=SimpleNamespace(request_digest="request"))
    asyncio.run(backend.idempotency_put("tenant-a", "key", "request", cached_response))
    with pytest.raises(ValueError, match="idempotency_key_reused"):
        asyncio.run(backend.idempotency_put("tenant-a", "key", "different", cached_response))
    session.get = AsyncMock(return_value=None)
    asyncio.run(backend.idempotency_put("tenant-a", "new", "request", cached_response))
    assert isinstance(session.add.call_args.args[0], IdempotencyRow)


class CommitSession:
    def __init__(
        self,
        workspace: WorkspaceRow,
        values: dict[type[object], object] | None = None,
    ) -> None:
        self.workspace = workspace
        self.values = values or {}
        self.added: list[object] = []
        self.flush_count = 0
        self.execute = AsyncMock()

    async def get(
        self,
        model: type[object],
        key: object,
        **_: object,
    ) -> object | None:
        if model is WorkspaceRow:
            return self.workspace
        return self.values.get(model)

    def add(self, value: object) -> None:
        self.added.append(value)

    async def flush(self) -> None:
        self.flush_count += 1


class QuarantiningStore(MemoryObjectStore):
    def __init__(self) -> None:
        super().__init__()
        self.quarantined: list[tuple[str, str, str]] = []

    def quarantine_unreferenced(self, tenant_id: str, digest: str, reason: str) -> None:
        self.quarantined.append((tenant_id, digest, reason))


def generation_mutation_fixture() -> tuple[GenerationMutation, QuarantiningStore]:
    store = QuarantiningStore()
    event = AuditEvent(
        metadata=metadata("event-commit"),
        spec=AuditEventSpec(
            event_id="event-commit",
            event_type="object_imported",
            occurred_at=NOW,
        ),
    )
    event_bytes = canonical_bytes(event.model_dump(mode="json", exclude_none=True))
    event_digest = store.put("tenant-a", event_bytes)
    prior = "sha256:" + "9" * 64
    placeholder = WorkspaceGeneration(
        metadata=metadata("generation-commit"),
        spec=WorkspaceGenerationSpec(
            generation_digest="sha256:" + "0" * 64,
            prior_generation_digest=prior,
            sequence=1,
            ledger=[
                LedgerEntry(
                    object_digest=event_digest,
                    object_kind="audit-event",
                    authority_status="active",
                )
            ],
            history_head_digest=document_digest(event),
        ),
    )
    generation = placeholder.model_copy(
        update={
            "spec": placeholder.spec.model_copy(
                update={"generation_digest": generation_digest(placeholder)}
            )
        }
    )
    api_response = response().model_copy(
        update={"generation_digest": generation.spec.generation_digest}
    )
    mutation = GenerationMutation(
        tenant_id="tenant-a",
        workspace_id="workspace-a",
        expected_generation=prior,
        generation=generation,
        audit_event=event,
        idempotency_key="i" * 16,
        request_digest="sha256:" + "8" * 64,
        response=api_response,
        object_admissions=(
            ObjectAdmission(
                object_digest=event_digest,
                object_kind="audit-event",
                authority_status="active",
                byte_length=len(event_bytes),
                object_key=f"cpcf/tenant-a/sha256/{event_digest[7:]}",
            ),
        ),
        outbox_topic="analysis",
        outbox_payload={"workspace_id": "workspace-a"},
    )
    return mutation, store


def _workspace_for(mutation: GenerationMutation) -> WorkspaceRow:
    return WorkspaceRow(
        tenant_id="tenant-a",
        workspace_id="workspace-a",
        current_generation_digest=mutation.expected_generation,
        generation_sequence=0,
        root_spki_fingerprint="sha256:" + "1" * 64,
        genesis_envelope_fingerprint="sha256:" + "2" * 64,
        created_at=NOW,
    )


def test_generation_mutation_validation_rejects_every_unbound_dimension() -> None:
    def rejected(
        mutation: GenerationMutation,
        store: QuarantiningStore,
        code: str,
    ) -> None:
        with pytest.raises(ValueError, match=code):
            _validate_generation_mutation(mutation, store)

    mutation, store = generation_mutation_fixture()
    rejected(replace(mutation, tenant_id="tenant-b"), store, "generation_tenant_mismatch")
    rejected(
        replace(mutation, workspace_id="workspace-b"),
        store,
        "generation_workspace_mismatch",
    )
    bad_generation = mutation.generation.model_copy(
        update={
            "spec": mutation.generation.spec.model_copy(
                update={"generation_digest": "sha256:" + "0" * 64}
            )
        }
    )
    rejected(replace(mutation, generation=bad_generation), store, "generation_digest_mismatch")
    rejected(
        replace(mutation, expected_generation="sha256:" + "7" * 64),
        store,
        "generation_predecessor_mismatch",
    )
    rejected(replace(mutation, idempotency_key="short"), store, "idempotency_key_length_invalid")
    rejected(
        replace(mutation, request_digest="sha256:" + "G" * 64), store, "request_digest_invalid"
    )
    rejected(
        replace(
            mutation,
            response=mutation.response.model_copy(
                update={"generation_digest": "sha256:" + "7" * 64}
            ),
        ),
        store,
        "response_generation_binding_mismatch",
    )
    wrong_head = mutation.generation.model_copy(
        update={
            "spec": mutation.generation.spec.model_copy(
                update={
                    "history_head_digest": "sha256:" + "7" * 64,
                    "generation_digest": "sha256:" + "0" * 64,
                }
            )
        }
    )
    wrong_head = wrong_head.model_copy(
        update={
            "spec": wrong_head.spec.model_copy(
                update={"generation_digest": generation_digest(wrong_head)}
            )
        }
    )
    rejected(
        replace(
            mutation,
            generation=wrong_head,
            response=mutation.response.model_copy(
                update={"generation_digest": wrong_head.spec.generation_digest}
            ),
        ),
        store,
        "generation_history_head_mismatch",
    )
    for field_name, code in (
        ("tenant_id", "audit_event_tenant_mismatch"),
        ("workspace_id", "audit_event_workspace_mismatch"),
    ):
        event = mutation.audit_event.model_copy(
            update={
                "metadata": mutation.audit_event.metadata.model_copy(update={field_name: "other"})
            }
        )
        generation = mutation.generation.model_copy(
            update={
                "spec": mutation.generation.spec.model_copy(
                    update={
                        "history_head_digest": document_digest(event),
                        "generation_digest": "sha256:" + "0" * 64,
                    }
                )
            }
        )
        generation = generation.model_copy(
            update={
                "spec": generation.spec.model_copy(
                    update={"generation_digest": generation_digest(generation)}
                )
            }
        )
        rejected(
            replace(
                mutation,
                audit_event=event,
                generation=generation,
                response=mutation.response.model_copy(
                    update={"generation_digest": generation.spec.generation_digest}
                ),
            ),
            store,
            code,
        )

    missing_store_mutation, missing_store = generation_mutation_fixture()
    del missing_store.values[
        ("tenant-a", missing_store_mutation.object_admissions[0].object_digest)
    ]
    rejected(missing_store_mutation, missing_store, "generation_ledger_invalid")
    admission = mutation.object_admissions[0]
    rejected(
        replace(mutation, object_admissions=(admission, admission)),
        store,
        "object_admission_digest_duplicate",
    )
    rejected(
        replace(
            mutation,
            object_admissions=(replace(admission, object_digest="sha256:" + "7" * 64),),
        ),
        store,
        "object_admission_not_in_generation",
    )
    rejected(
        replace(mutation, object_admissions=(replace(admission, object_kind="wrong-kind"),)),
        store,
        "object_admission_ledger_mismatch",
    )
    rejected(
        replace(mutation, object_admissions=(replace(admission, byte_length=0),)),
        store,
        "object_admission_length_mismatch",
    )
    rejected(
        replace(mutation, object_admissions=(replace(admission, object_key="../escape"),)),
        store,
        "object_admission_key_not_tenant_digest_scoped",
    )
    digest = admission.object_digest
    rejected(
        replace(mutation, quarantine_additions=((digest, "one"), (digest, "two"))),
        store,
        "quarantine_addition_duplicate",
    )
    rejected(
        replace(mutation, quarantine_resolutions=(digest, digest)),
        store,
        "quarantine_resolution_duplicate",
    )


def test_generation_unit_of_work_commits_all_database_effects_or_quarantines() -> None:
    mutation, store = generation_mutation_fixture()
    workspace = WorkspaceRow(
        tenant_id="tenant-a",
        workspace_id="workspace-a",
        current_generation_digest=mutation.expected_generation,
        generation_sequence=0,
        root_spki_fingerprint="sha256:" + "1" * 64,
        genesis_envelope_fingerprint="sha256:" + "2" * 64,
        created_at=NOW,
    )
    session = CommitSession(workspace)
    backend = backend_with(session)
    committed = asyncio.run(backend.commit_generation(mutation, store))
    assert committed.generation_digest == mutation.generation.spec.generation_digest
    assert workspace.current_generation_digest == mutation.generation.spec.generation_digest
    assert workspace.generation_sequence == 1
    assert {type(item) for item in session.added}.issuperset(
        {ObjectRow, GenerationRow, LedgerRow, AuditEventRow, OutboxRow, IdempotencyRow}
    )
    assert session.flush_count == 2
    assert not store.quarantined

    failed = backend_with(session, RuntimeError("transaction_interrupted"))
    with pytest.raises(RuntimeError, match="transaction_interrupted"):
        asyncio.run(failed.commit_generation(mutation, store))
    assert store.quarantined == [
        (
            "tenant-a",
            mutation.object_admissions[0].object_digest,
            "database_transaction_rolled_back",
        )
    ]


def test_generation_unit_of_work_replay_predecessor_object_and_quarantine_branches() -> None:
    mutation, store = generation_mutation_fixture()
    cached = IdempotencyRow(
        tenant_id="tenant-a",
        idempotency_key=mutation.idempotency_key,
        request_digest=mutation.request_digest,
        response_status=200,
        response_body=canonical_bytes(mutation.response.model_dump(mode="json")),
        expires_at=NOW + timedelta(days=1),
    )
    replay_workspace = _workspace_for(mutation)
    replay_workspace.current_generation_digest = mutation.generation.spec.generation_digest
    replay_workspace.generation_sequence = 1
    replay_session = CommitSession(replay_workspace, {IdempotencyRow: cached})
    assert (
        asyncio.run(backend_with(replay_session).commit_generation(mutation, store))
        == mutation.response
    )
    assert not replay_session.added
    cached.request_digest = "sha256:" + "7" * 64
    with pytest.raises(ValueError, match="idempotency_key_reused"):
        asyncio.run(
            backend_with(
                CommitSession(_workspace_for(mutation), {IdempotencyRow: cached})
            ).commit_generation(mutation, store)
        )

    wrong_sequence = _workspace_for(mutation)
    wrong_sequence.generation_sequence = 3
    with pytest.raises(ValueError, match="generation_sequence_mismatch"):
        asyncio.run(backend_with(CommitSession(wrong_sequence)).commit_generation(mutation, store))
    with pytest.raises(ValueError, match="object_admission_required"):
        asyncio.run(
            backend_with(CommitSession(_workspace_for(mutation))).commit_generation(
                replace(mutation, object_admissions=()), store
            )
        )
    stored = ObjectRow(
        tenant_id="tenant-a",
        object_digest=mutation.object_admissions[0].object_digest,
        object_kind="wrong-kind",
        authority_status="active",
        byte_length=mutation.object_admissions[0].byte_length,
        object_key=mutation.object_admissions[0].object_key,
        created_at=NOW,
    )
    with pytest.raises(ValueError, match="stored_object_metadata_mismatch"):
        asyncio.run(
            backend_with(
                CommitSession(_workspace_for(mutation), {ObjectRow: stored})
            ).commit_generation(mutation, store)
        )
    prior = GenerationRow(
        tenant_id="tenant-a",
        workspace_id="workspace-a",
        generation_digest=mutation.expected_generation,
        sequence=0,
        prior_generation_digest=None,
        manifest={"spec": {"history_head_digest": "sha256:" + "7" * 64}},
        created_at=NOW,
    )
    with pytest.raises(ValueError, match="audit_event_predecessor_mismatch"):
        asyncio.run(
            backend_with(
                CommitSession(_workspace_for(mutation), {GenerationRow: prior})
            ).commit_generation(mutation, store)
        )

    digest = mutation.object_admissions[0].object_digest
    quarantine_mutation = replace(
        mutation,
        quarantine_additions=((digest, "manual_review"),),
        outbox_topic=None,
    )
    quarantine_session = CommitSession(_workspace_for(mutation))
    asyncio.run(backend_with(quarantine_session).commit_generation(quarantine_mutation, store))
    assert any(isinstance(item, QuarantineRow) for item in quarantine_session.added)

    existing = QuarantineRow(
        tenant_id="tenant-a",
        workspace_id="workspace-a",
        object_digest=digest,
        reason_code="old_reason",
        quarantined_at=NOW - timedelta(days=1),
    )
    update_session = CommitSession(_workspace_for(mutation), {QuarantineRow: existing})
    asyncio.run(backend_with(update_session).commit_generation(quarantine_mutation, store))
    assert existing.reason_code == "manual_review" and existing.resolved_at is None

    resolution = replace(
        mutation,
        quarantine_resolutions=(digest,),
        outbox_topic=None,
    )
    active = QuarantineRow(
        tenant_id="tenant-a",
        workspace_id="workspace-a",
        object_digest=digest,
        reason_code="manual_review",
        quarantined_at=NOW,
    )
    asyncio.run(
        backend_with(
            CommitSession(_workspace_for(mutation), {QuarantineRow: active})
        ).commit_generation(resolution, store)
    )
    assert active.resolved_at is not None
    with pytest.raises(ValueError, match="quarantine_resolution_not_active"):
        asyncio.run(
            backend_with(CommitSession(_workspace_for(mutation))).commit_generation(
                resolution, store
            )
        )


def test_postgres_authoritative_read_rejects_database_manifest_divergence() -> None:
    mutation, store = generation_mutation_fixture()
    workspace = WorkspaceRow(
        tenant_id="tenant-a",
        workspace_id="workspace-a",
        current_generation_digest=mutation.generation.spec.generation_digest,
        generation_sequence=1,
        root_spki_fingerprint="sha256:" + "1" * 64,
        genesis_envelope_fingerprint="sha256:" + "2" * 64,
        created_at=NOW,
    )
    generation_row = GenerationRow(
        tenant_id="tenant-a",
        workspace_id="workspace-a",
        generation_digest=mutation.generation.spec.generation_digest,
        sequence=1,
        prior_generation_digest=mutation.expected_generation,
        manifest=mutation.generation.model_dump(mode="json", exclude_none=True),
        created_at=NOW,
    )

    async def get(model: type[object], *_: object, **__: object) -> object | None:
        if model is WorkspaceRow:
            return workspace
        if model is GenerationRow:
            return generation_row
        return None

    session = SimpleNamespace(
        get=AsyncMock(side_effect=get),
        execute=AsyncMock(side_effect=[Result(), ScalarRows([])]),
    )
    policy, trusted_time, _ = trust_fixture()
    missing_workspace = SimpleNamespace(
        get=AsyncMock(return_value=None), execute=AsyncMock(return_value=Result())
    )
    with pytest.raises(ValueError, match="workspace_not_found"):
        asyncio.run(
            backend_with(missing_workspace).authoritative_view(
                "tenant-a",
                "workspace-a",
                store,
                policy=policy,
                trusted_time=trusted_time,
            )
        )

    missing_generation = SimpleNamespace(
        get=AsyncMock(side_effect=[workspace, None]),
        execute=AsyncMock(return_value=Result()),
    )
    with pytest.raises(ValueError, match="workspace_generation_not_admitted"):
        asyncio.run(
            backend_with(missing_generation).authoritative_view(
                "tenant-a",
                "workspace-a",
                store,
                policy=policy,
                trusted_time=trusted_time,
            )
        )

    wrong_document_row = SimpleNamespace(
        manifest=mutation.audit_event.model_dump(mode="json", exclude_none=True)
    )
    wrong_document = SimpleNamespace(
        get=AsyncMock(side_effect=[workspace, wrong_document_row]),
        execute=AsyncMock(return_value=Result()),
    )
    with pytest.raises(ValueError, match="workspace_generation_document_required"):
        asyncio.run(
            backend_with(wrong_document).authoritative_view(
                "tenant-a",
                "workspace-a",
                store,
                policy=policy,
                trusted_time=trusted_time,
            )
        )

    with pytest.raises(RuntimeError, match="database_ledger_manifest_mismatch"):
        asyncio.run(
            backend_with(session).authoritative_view(
                "tenant-a",
                "workspace-a",
                store,
                policy=policy,
                trusted_time=trusted_time,
            )
        )

    entry = mutation.generation.spec.ledger[0]
    ledger_row = LedgerRow(
        tenant_id="tenant-a",
        workspace_id="workspace-a",
        generation_digest=mutation.generation.spec.generation_digest,
        object_digest=entry.object_digest,
        object_kind=entry.object_kind,
        authority_status=entry.authority_status,
        source_digests=list(entry.source_digests),
    )
    matching = SimpleNamespace(
        get=AsyncMock(side_effect=[workspace, generation_row]),
        execute=AsyncMock(side_effect=[Result(), ScalarRows([ledger_row])]),
    )
    view = asyncio.run(
        backend_with(matching).authoritative_view(
            "tenant-a",
            "workspace-a",
            store,
            policy=policy,
            trusted_time=trusted_time,
        )
    )
    assert not view.valid
    assert "active_trust_policy_not_signed_in_generation" in view.reasons


def test_worker_claim_query_missing_configuration_empty_and_available_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sqlalchemy.ext.asyncio
    from cpcf_worker import main as worker_main

    monkeypatch.delenv("CPCF_DATABASE_URL", raising=False)
    monkeypatch.delenv("CPCF_WORKER_TENANT", raising=False)
    with pytest.raises(RuntimeError, match="required"):
        asyncio.run(worker_main.run_once())

    monkeypatch.setenv("CPCF_DATABASE_URL", "postgresql+psycopg://example")
    monkeypatch.setenv("CPCF_WORKER_TENANT", "tenant-a")
    monkeypatch.setattr("cpcf_api.db.make_engine", lambda _: object())
    session = SimpleNamespace(execute=AsyncMock(return_value=Result(scalar=None)))
    sessions = Sessions(session)
    monkeypatch.setattr(
        sqlalchemy.ext.asyncio,
        "async_sessionmaker",
        lambda *args, **kwargs: sessions,
    )
    assert asyncio.run(worker_main.run_once()) == 0
    session.execute = AsyncMock(return_value=Result(scalar="message-id"))
    assert asyncio.run(worker_main.run_once()) == 1
