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

The 0.6 and 0.7 series are published with the package classifier `Development Status :: 4 - Beta`.
The release workflow uses the explicit `beta` publication class, which permits OSS package
distribution without treating absent external evidence as satisfied. A Beta package release is not
an operational-assurance decision.

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
Mutmut indices modulo five. Every shard keeps the original frozen configuration, mutation
targets, coverage-based generation, test selection, baseline checks and per-mutant timeouts.
Each shard's execution step is bounded to 300 minutes so a step timeout can still retain its
complete diagnostic status list before the hosted job limit.

The required `mutation` job runs even when a shard fails and explicitly rejects that failure.
After all five succeed, it downloads their full reports and runs:

```text
uv run --frozen python -m scripts.merge_mutation_results mutation-shards mutation-results.txt --catalogue audit/mutation-catalogue-v0.7.json
uv run --frozen python scripts/check_mutation_score.py mutation-results.txt --minimum 85
```

The merger requires identical complete catalogues and the reviewed Mutmut version, count
and SHA-256 fingerprint in `audit/mutation-catalogue-v0.7.json`. That record was generated
from the complete local 0.7.0 run: 12,284 unique names. Its fingerprint is the SHA-256 of
UTF-8 sorted names, each followed by a newline. It identifies catalogue membership, not
empirical evidence or source authenticity; the CI commit binds the source and execution.

Missing or altered members, duplicate lines, unexpected shards/files, unknown statuses,
incomplete owner results and execution assigned to the wrong shard all fail closed. Only
the assigned shard supplies each mutant's terminal status. The full union retains surviving,
untested, timeout, suspicious and segfault results as failures under the unchanged 85% gate.
Raw shard artifacts and the combined report remain available for 14 days.

If reviewed source, test selection or a pinned Mutmut update changes the generated catalogue,
produce and inspect a complete native result before regenerating its version/count/fingerprint.
Do not refresh the record merely to silence a mismatch or copy a partial passing subset.
