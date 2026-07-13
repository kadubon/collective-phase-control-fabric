# CPCF Agent Instructions

## Immutable claim boundaries

- CPCF projects external records; source systems retain source-of-record authority.
- Never infer success, acceptance, authorization, truth, causality, independence, or physical outcome
  from unknown data, an exit code, a model label, a role name, or missing exposure records.
- Never claim collective superintelligence, consciousness, a physical phase transition,
  thermodynamic feasibility, statistical validity, causality, or measured acceleration.
- Never execute an adapter in the API or analysis worker. v0.6 execution is an external-runner
  protocol only.
- Never execute v0.1–v0.5 actions or reinterpret their authority. Import raw bytes into quarantine.
- Never accept a self-carried key, cached validation Boolean, unsigned time, or unsigned capability as
  authority.
- Before any push, run the source, staged-content, Gitleaks, and built-artifact hygiene checks. A
  source push still does not authorize a tag, release, deployment, or PyPI upload.

## Setup and checks

```text
uv sync --frozen --all-extras --group dev --group security
uv run --frozen ruff format --check .
uv run --frozen ruff check .
uv run --frozen mypy src packages/cpcf-api/src packages/cpcf-cli/src packages/cpcf-worker/src packages/cpcf-runner-protocol/src
uv run --frozen pytest
uv run --frozen pytest --cov=collective_phase_control_fabric --cov=cpcf_api --cov-report=term-missing --cov-fail-under=90
uv run --frozen bandit -c pyproject.toml -r src packages
uv run --frozen python scripts/check_schemas.py
uv run --frozen python scripts/check_fixtures.py
uv run --frozen python scripts/generate_references.py --check
uv run --frozen python scripts/check_publication_hygiene.py --source-tree
uv build
```

Use the checked-in `uv.lock`. Do not regenerate it as a side effect of an unrelated command.

Core and CLI checks must work in PowerShell, cmd-compatible Python execution, and POSIX shells on
Windows and Linux. PostgreSQL, S3, OIDC, KMS, OCI, and Kubernetes are required only for server and
deployment integration tests, never for offline core inspection.

## v0.6 module map

- `v6/models.py`, `v6/registry.py`, `v6/canonical.py`: closed documents, schema identity, and bounded
  parsing.
- `v6/trust.py`, `v6/kms.py`: DSSE, historical time, pinned identity, and role quorum.
- `v6/science.py`, `v6/coordination.py`: shared exact snapshot and perturbation audit.
- `v6/planning.py`: branch-safe Pareto and strong AND–OR planning.
- `v6/runner.py`, `v6/projection.py`: external runner receipts and independent projection.
- `v6/trials.py`: registration and external evidence compatibility.
- `v6/storage.py`: immutable ledger and copy-on-write legacy boundary.
- `packages/cpcf-api`: optional OIDC/RLS/S3 control plane; no adapter execution.
- `packages/cpcf-worker`: typed analysis jobs only.

Every public semantic change requires a closed schema, stable failure code, negative regression test,
and audit-registry update.

The repository produces one distribution, `collective-phase-control-fabric`, while preserving the
five import packages. Do not reintroduce dependencies on unpublished `cpcf-*` distributions.
