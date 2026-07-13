# Installed-Wheel Tutorial

This tutorial uses only non-production local data. It performs no publication, networked adapter
execution, or external experiment.

## 1. Install and orient

```text
python -m venv .tutorial-venv
.tutorial-venv\Scripts\python -m pip install collective-phase-control-fabric
.tutorial-venv\Scripts\cpcf agent explain --json
.tutorial-venv\Scripts\cpcf self-check --json
.tutorial-venv\Scripts\cpcf schema list --json
```

On POSIX systems use `.tutorial-venv/bin/`. Verify that the explanation identifies the native result
as `operational_organization_profile` and lists the nonclaims.

## 2. Inspect a closed schema

```text
cpcf schema show phase-contract --json
cpcf schema show state-attestation --json
cpcf schema show unknown-kind --json
```

The unknown kind must return `unknown_document_kind` and suggest `schema list`; it must not infer a
mapping.

## 3. Verify a portable bundle

```text
cpcf bundle verify BUNDLE_DIRECTORY --json
```

A digest-consistent unsigned bundle reports `content_consistent` and authenticity `unknown`. Modify
a copied bundle object and rerun the command; verification must fail without promoting any content.

## 4. Install optional services

Running `cpcf-api` from the base install reports the required extra. Install it explicitly:

```text
pip install "collective-phase-control-fabric[server,solver]"
```

A real API also requires PostgreSQL, OIDC, object storage, and explicit trusted roots. The reference
deployment is not a substitute for the incomplete release gates.

## 5. Remote onboarding

With an authorized control plane:

```text
set CPCF_API_URL=https://cpcf.example.org
set CPCF_TOKEN=OIDC_ACCESS_TOKEN
cpcf workspace status WORKSPACE --json
cpcf agent onboard --workspace WORKSPACE --json
```

The response must carry the immutable generation, unknowns, quarantined objects, and exact safe
commands. The current reference API does not yet aggregate every trust, science, runner, projection,
coordination, and trial subsystem; that is an explicit stable-release blocker.

For offline runner receipt checking, use the closed job, receipt, capability, execution-policy, and
artifact records:

```text
cpcf runner conformance runner-job.json runner-receipt.json adapter-capability.json execution-policy.json --runner-principal RUNNER --received-at 2026-01-01T00:00:00+00:00 --artifact sha256:DIGEST=artifact.bin --json
```

This command executes no adapter and promotes no projection. Successful execution still creates a
pending projection that requires independent, source-pointer-reconstructing approval.
