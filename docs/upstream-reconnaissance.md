# Upstream Reconnaissance

Reconnaissance was repeated on 2026-07-13 against the local source checkouts and their
installed executable surfaces. No provider, network connector, mutation command, git command,
experiment, or benchmark was run.

## Collective Capability Runtime

- Source checkout: `<CCR_SOURCE_CHECKOUT>` (outside this repository)
- Source-declared version: 1.6.0
- Editable package metadata observed through `pip show`: 1.1.0
- Executable: `ccr.exe` from the Python 3.13 Scripts directory
- Confirmed read-only operation: `ccr agent explain --json`.
- `agent explain` currently exposes `ok`, `agent_manifest`, `default_mode`, documentation,
  safe boundaries, safe next commands, runtime paths, and version-specific runtime metadata.
- `storage doctor` exposes `ok`, backend, database, integrity, schema version, blockers,
  foreign-key errors, outbox status, and reconciliation information.

The adapter records source-declared, package-metadata, and report-declared versions separately.
The discrepancy above is not resolved by assumption.

## Percolation Inversion Compiler

- Source checkout: `<PIC_SOURCE_CHECKOUT>` (outside this repository)
- Source and executable report version: 1.1.0
- Editable package metadata observed through `pip show`: 0.6.0
- Executable: `pic.exe` from the Python 3.13 Scripts directory
- Confirmed read-only operations include `pic agent explain`, `pic agent check --compact`,
  `pic phase plan --compact`, `pic audit canonical-readiness`, and `pic schema`.
- The compact agent check exposes `accepted`, `operationally_usable`, `settled`, reasons,
  unresolved obligations, residual summary, safety invariants, and schema references.
- The compact phase plan exposes finite-check status, phase-gap data, blockers, candidate-only
  reasons, safe commands, SDK calls, and settlement blockers.
- Public schemas were inspected for `AgentIntakeReport` and `PhaseAccelerationPlan`.

## Adapter decision

CPCF v0.2.0 supports only the confirmed read-only report shapes. All five registered operations
(`ccr` agent explanation; `pic` agent explanation, agent check, phase plan, and
canonical readiness) completed their current handshakes and required-key checks on 2026-07-13.
The capability registry maps exact source JSON pointers to named target schemas and never infers
fields. Direct adapter invocation does not persist output beside an upstream checkout; durable
projection requires an authenticated source-import workflow in a CPCF workspace. Exit status is never mapped to
acceptance, acceptance is never mapped to settlement, and safe-command text is never executed.
Unknown or changed fields produce a malformed or unsupported-version blocker.

`ccr storage doctor` was removed from the registered surface after this audit observed that it can
create `ccr.sqlite` in the selected root. CPCF retains its observed report schema but will not call
that operation as read-only.
