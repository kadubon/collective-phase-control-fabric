# Collective Phase Control Fabric

Collective Phase Control Fabric (CPCF) is an evidence-control toolkit for finite collective
workflows. It validates provenance, exact resource constraints, causal formation, catalytic
support, verification capacity, independence, perturbations, coordination, and externally
registered trial bindings.

CPCF reports an `operational_organization_profile`. It does not create, detect, or certify a
collective-superintelligence phase. It also does not certify causality, statistical validity,
thermodynamic feasibility, physical phase behavior, or runner isolation.

> Release status: v0.6.0 is a Beta research package. Package publication does not establish
> deployment assurance. Operational evidence remains unavailable until the external security,
> restore, soak, and independent-review gates in [release readiness](docs/release-readiness.md) pass.

## Install

The one public distribution contains the offline core, CLI, schema registry, bundle verifier,
runner protocol models, and all import packages.

```text
pip install collective-phase-control-fabric
pipx install collective-phase-control-fabric
pip install "collective-phase-control-fabric[server,solver]"
```

Available extras are `server`, `worker`, `runner`, `solver`, `aws-kms`, `gcp-kms`, `azure-kms`,
`pkcs11`, and `all`. Service commands detect missing extras and print the exact installation
command.

## Five-minute offline orientation

These commands do not require an API or credentials:

```text
cpcf agent explain --json
cpcf self-check --json
cpcf schema list --json
cpcf schema show phase-contract --json
cpcf bundle verify PATH_TO_BUNDLE --json
```

An unsigned bundle can establish content consistency only. Distribution authenticity remains
unknown unless the bundle carries an admitted root attestation and a trust policy is supplied.

## Remote workspace use

Remote operations require a configured control plane and a short-lived OIDC access token. The CLI
does not persist bearer tokens.

```text
set CPCF_API_URL=https://cpcf.example.org
set CPCF_TOKEN=OIDC_ACCESS_TOKEN
cpcf workspace create WORKSPACE --root-spki-fingerprint sha256:ROOT_SPKI_SHA256 --genesis-envelope-fingerprint sha256:GENESIS_ENVELOPE_SHA256 --json
cpcf workspace status WORKSPACE --json
cpcf agent onboard --workspace WORKSPACE --json
```

On POSIX shells, use `export`. Mutations require an `Idempotency-Key`; changes to existing
workspaces also require the expected immutable generation through `If-Match`.

## Operational profile

Each required dimension is `satisfied`, `violated`, `unknown`, or `unknown_due_to_budget`:

1. provenance integrity
2. trust quorum
3. temporal integrity
4. structural reachability
5. causal formation
6. dimensional consistency
7. exact self-maintenance
8. finite-horizon resource persistence
9. target-bound generative catalysis
10. verification capacity
11. effective independence
12. coordination protocol integrity
13. perturbation robustness

Compatibility requires every required dimension to be satisfied in one immutable analysis
snapshot. Hypothetical planner output cannot satisfy a scientific dimension before receipt-backed
promotion.

## Development

Contributors use the checked-in universal `uv.lock`; pip is only a consumer installation path.
Development uses CPython 3.14.6 and supports CPython 3.12–3.14 on Windows and Linux.

```text
uv sync --frozen --all-extras --group dev --group security
uv run --frozen ruff format --check .
uv run --frozen ruff check .
uv run --frozen mypy src packages/cpcf-api/src packages/cpcf-cli/src packages/cpcf-worker/src packages/cpcf-runner-protocol/src
uv run --frozen pytest
uv run --frozen python scripts/check_schemas.py
uv run --frozen python scripts/generate_references.py --check
uv run --frozen python scripts/check_publication_hygiene.py --source-tree
uv build
```

The root project builds exactly one wheel and one source distribution named
`collective-phase-control-fabric`. The five import packages remain
`collective_phase_control_fabric`, `cpcf_cli`, `cpcf_api`, `cpcf_worker`, and
`cpcf_runner_protocol`.

## Documentation

- [Documentation index](docs/index.md)
- [Installation](docs/installation.md)
- [Offline orientation](docs/offline-orientation.md)
- [Remote workspace use](docs/remote-workspaces.md)
- [Evidence model](docs/evidence-model.md)
- [Scientific boundaries](docs/scientific-boundaries.md)
- [Security and publication hygiene](docs/security.md)
- [Complete installed-wheel tutorial](docs/tutorial-v0.6/README.md)
- [Release readiness](docs/release-readiness.md)

## License and security

All repository content is English and licensed under Apache-2.0. Report vulnerabilities using the
private process in [SECURITY.md](SECURITY.md); never include credentials, tenant evidence, or live
endpoints in a public issue.
