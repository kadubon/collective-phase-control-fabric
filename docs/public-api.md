# Maintained CPCF 1.x public API

The intended 1.0.0 public surface is the `collective_phase_control_fabric.growth_control`
facade, registered `cpcf` CLI, and closed document schemas. The release remains
**Development Status :: 4 - Beta**. API maintenance does not establish production
assurance or external scientific validity. See the [verification matrix](roadmap-to-1.0.md)
for release readiness; this document is not a publication receipt.

The distribution remains `collective-phase-control-fabric`, with the existing
five import packages. Unlisted implementation modules and private helpers are
not independently frozen APIs. Existing no-opt-in growth documents retain their
protocol identity and historical semantics.

## Python facade

Import the functions below from `collective_phase_control_fabric.growth_control`.
Closed documents are obtained through `parse_document(dict)` or
`parse_document_bytes(bytes)` and serialized using `model_dump(mode="json")`.
Rationals are strings; floating-point model quantities are rejected. Input
documents and object mappings must not be modified during a call or while a
`Domain` is reused; construct a new domain for changed inputs.

| Operation | Arguments | Result |
| --- | --- | --- |
| `Domain` | growth contract, digest-keyed document map, epistemic sidecar, optional frontier; optional observation map and excluded action/interaction sets | Validated finite planning domain |
| `canonical_support`, `support_digest` | Compatible hypothesis list / canonical support tuple | Canonical full correlated support / digest |
| `plan_epistemic` | Domain, optional visible `EpistemicStep` history | Closed `epistemic-plan` including completeness and optional incumbent |
| `check_epistemic_plan` | Domain, plan | Feasibility/objective report; `global_optimality_checked=false` |
| `compare_epistemic` | Domain, optional history | Reoptimized restricted comparison records |
| `information_value` | Domain, total deterministic masked-channel map, optional sensing action IDs | Closed `information-value` containing three policies and typed differences |
| `synthesize` | Domain, closed workflow request | Closed synthesis result, proposed charged sidecar, checked candidates and certificates |
| `check_composition` | Domain, request, candidate | Fresh finite-domain certificate, or failure |
| `propose_catalogue` | Domain, request, synthesis, candidate; optional keyword `parent` revision | Unsigned closed catalogue revision |
| `replan_catalogue` | Domain, request, candidate, certificate, revision; keyword `model_only_opt_in=True` required | Freshly checked model replan report |
| `export_epistemic` | Domain, checked plan, operator-supplied primitive runner-job draft | Unsigned proposed job; no execution |
| `reassess_epistemic`, `replan_epistemic` | Domain, epistemic observation, original growth observation, existing admission keyword arguments | Fresh evidence assessment / unsigned replan |

Admission arguments are the existing generation, object store, trust policy,
trusted time and pinned genesis/root fingerprints. They are original inputs to
validation, not cached acceptance flags. No facade function writes trust records,
signs documents, dispatches an adapter or grants execution authority.

`GrowthError` is a `ValueError` with a stable `.code`. Closed-document parsing uses
`DocumentValidationError` (also `ValueError`, with `.code`); malformed byte encodings
and lexical bounds raise `ValueError`. Bounded planner exhaustion is represented
in result `spec.code` and `spec.search.complete`, rather than converted into a
successful proof. Filesystem and transport errors remain their native exceptions.

## CLI and JSON

Existing growth commands remain available. Supply `--epistemic` to opt into the
new semantics, alongside the existing contract, `--objects` and optional
`--frontier`. `--history` is a JSON array of action/visible-observation steps.
New commands are `support`, `information-value`, `synthesize`, `check-composition`,
`catalogue-propose` and `catalogue-replan`. The latter requires `--model-only`.
Epistemic replay uses `--observation-symbol`; legacy replay retains `--branch`.
The generated [CLI reference](reference/generated/cli.json) is the authoritative flag listing.

Consumers should inspect the complete JSON result. Closed result documents retain
`api_version`, `kind`, `metadata`, `spec`, input/checker digests, policy/objective,
search completeness and explicit model/evidence boundaries as applicable. A valid
command result is not itself a capability admission or proof of global optimality.
Text output is for humans and is not a parsing API. `--output` writes the complete
JSON result; it never requests execution.

Growth commands exit 0 when they emit a result, including an explicitly unknown
or no-entry result. They exit 1 on handled input/checking failures, with a JSON
`status=error` and stable `code`. Argument syntax errors use argparse exit 2.
Callers must inspect completeness and evidence fields rather than infer growth
or authorization from exit 0.

Incompatible changes to this maintained surface require a major package version.
Additive functionality uses a minor version and new closed document kinds when
old schema identity would otherwise change. Deprecations must be documented in
the changelog with a replacement and remain available throughout the current
major version. Historical schema goldens must not be regenerated to hide drift.

No external empirical acceleration experiment was performed. API version 1.0.0
does not establish real-world capability reproduction, collective intelligence,
AGI, ASI, causal acceleration or indefinite growth.
