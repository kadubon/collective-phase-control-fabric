# Release Process

The GitHub repository, workflow, and PyPI project identifiers are fixed:

- repository: `kadubon/collective-phase-control-fabric`
- workflow: `.github/workflows/workflow.yml`
- PyPI project: `collective-phase-control-fabric`
- protected GitHub environment: `pypi`

`workflow_dispatch` performs verification only. PyPI publication is eligible only for a
non-prerelease GitHub Release whose `vX.Y.Z` tag exactly matches package metadata. The publish job
also requires the repository variable `PYPI_PUBLISH_ENABLED=true` and approval in the protected
`pypi` environment.

The 0.6 and 0.7 series and the 1.0 release target use the classifier `Development Status :: 4 - Beta`.
The release workflow uses the explicit `beta` publication class, which permits OSS package
distribution without treating absent external evidence as satisfied. A Beta package release is not
an operational-assurance decision.

The 1.0 target defines a maintained public API, not production maturity. Its
qualification matrix is [tracked separately](roadmap-to-1.0.md). Complete the new
epistemic/composition coverage and expanded mutation catalogue before release;
the historical 0.7 catalogue below is not sufficient for changed source. Required
checks, merge authorization and the actual Wiki update are release prerequisites.
The specific owner-authorized 1.0 review exception is recorded in the requirement
matrix; it does not waive any verification or publication environment gate.

Operational assurance separately requires `release-evidence/vX.Y.Z.json`. The strict default mode
checks exact version and commit bindings and requires passed availability-soak,
intended-deployment restore, load, chaos, independent threat-model, and independent
penetration-test evidence. The manifest remains absent until those activities have actually
completed.

The trusted publisher is configured for environment `pypi`. Its GitHub environment reviewer is
`kadubon` with `prevent_self_review=false`. This is self-approval rather than independent release
review. It can authorize Beta package distribution, but it cannot satisfy the independent
operational-review requirements in [release readiness](release-readiness.md).

Every upload requires the repository, workflow filename, environment, project name and OIDC
claims to match exactly. The growth extension also runs deterministic examples and an installed
base-wheel growth command in the release gate. Neither publication nor a model witness establishes
the external operational evidence listed above.

## Complete mutation assurance within hosted job limits

CI and release run the same five selectors: `*__mutmut_*[05]`, `*__mutmut_*[16]`,
`*__mutmut_*[27]`, `*__mutmut_*[38]`, and `*__mutmut_*[49]`. They partition positive
Mutmut indices modulo five. Every shard uses the same frozen configuration, mutation
targets, coverage-based generation, test selection, baseline checks and per-mutant timeouts.
Each shard's execution step is bounded to 300 minutes so a step timeout can still retain its
complete diagnostic status list before the hosted job limit.

The required `mutation` job runs even when a shard fails and explicitly rejects that failure.
After all five succeed, it downloads their full reports and runs:

```text
uv run --frozen python -m scripts.merge_mutation_results mutation-shards mutation-results.txt --catalogue audit/mutation-catalogue-v1.0.json
uv run --frozen python -m scripts.check_mutation_scope mutation-results.txt
uv run --frozen python scripts/check_mutation_score.py mutation-results.txt --minimum 85
```

The merger requires identical complete catalogues and the reviewed Mutmut version, count
and SHA-256 fingerprint in `audit/mutation-catalogue-v1.0.json`: 17,581 unique names
from the complete generated native catalogue, including all configured modules
and required control methods. The historical 0.7 record remains unchanged at
12,284 names. Each fingerprint is the SHA-256 of
UTF-8 sorted names, each followed by a newline. It identifies catalogue membership, not
empirical evidence or source authenticity; the CI commit binds the source and execution.

Missing or altered members, duplicate lines, unexpected shards/files, unknown statuses,
incomplete owner results and execution assigned to the wrong shard all fail closed. Only
the assigned shard supplies each mutant's terminal status. The full union retains surviving,
untested, timeout, suspicious and segfault results as failures under the unchanged 85% gate.
Raw shard artifacts and the combined report remain available for 14 days.

The pinned Mutmut excludes decorated classes. Epistemic control and policy search
therefore use ordinary classes so their actual methods are mutated. Its import
and mutation names do not agree for nested source roots. The isolated workspace
preparer copies source into one `src` root and verifies every file's SHA-256.
Only mutation source placement/path settings change: the lock, source bytes,
test selection, operators and timeouts remain fixed. Per-shard source maps are
retained as separate artifacts. The baseline checks every target's actual import
origin. `scripts.check_mutation_scope` rejects a catalogue missing any
configured module or a required epistemic control method, independently of the
membership fingerprint and the full execution/score gates. Scope membership
alone is not a passing mutation result.

If reviewed source, test selection or a pinned Mutmut update changes the generated catalogue,
produce and inspect the complete native catalogue/status inventory before regenerating
its version/count/fingerprint. Membership may be reviewed while execution continues;
it cannot qualify execution, waive a shard failure or establish a score. Never select
only passing mutants or refresh the record merely to silence a mismatch. Release still
requires complete terminal results, every shard's success and the unchanged 85% gate.
