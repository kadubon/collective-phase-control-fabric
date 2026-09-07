# Growth P0 validation record

This record concerns a finite offline reference implementation. Synthetic test receipts are
fixtures, not operational evidence. Beta package publication does not establish scientific or
deployment assurance. See [release readiness](release-readiness.md) for the actual gate results.

## Changed surfaces

- `v6/models.py` and the registry add four closed growth documents and exact rational ledgers.
- `v6/growth.py` implements finite AND-OR planning, reoptimized scalar comparison, protected
  prefix accounting, paid continuation, explicit search/witness bounds and independent checking.
- `v6/growth_evidence.py` connects read-only replay, unsigned proposals, fresh DSSE/quorum,
  registered trial and receipt compatibility, physical time, reassessment and unsigned replanning.
- `v6/authority.py` binds observation roles; `v6/storage.py` keeps typed-looking raw bytes opaque.
- `cpcf_cli/growth.py` provides inspect, plan, check-plan, compare, export, replay, ingest,
  reassess, replan and executable examples in the base wheel.
- Three test modules, frozen original golden inputs, schemas, generated references, formal and
  scientific documentation, the repository skill and Wiki cover the new path and its boundaries.
- CI and release retain the 90% overall, 95% critical/per-subsystem and 85% mutation gates.
  Growth is included as a thirteenth critical group and in the mutation selection.
- API/worker image recipes pin the Alpine OpenSSL/libuuid fixes reported by the existing
  scheduled scanner. Updating those recipes does not deploy a service.

## Reproduce

Use the frozen environment and all commands in [AGENTS.md](../AGENTS.md). Additional gates are:

```text
uv run --frozen mypy src packages/cpcf-api/src packages/cpcf-cli/src packages/cpcf-worker/src packages/cpcf-runner-protocol/src scripts
uv run --frozen pytest --cov=collective_phase_control_fabric --cov=cpcf_api --cov=cpcf_cli --cov=cpcf_worker --cov=cpcf_runner_protocol --cov-branch --cov-report=term-missing --cov-fail-under=90
uv run --frozen python scripts/check_critical_coverage.py critical-coverage.json --minimum 95
uv run --frozen pip-audit --local --cache-dir .cache/pip-audit --vulnerability-service osv --timeout 60
uv run --frozen python scripts/run_growth_examples.py --check
uv run --frozen mutmut run
uv run --frozen mutmut results --all true
```

The exact focused test selection producing `critical-coverage.json` is in
`.github/workflows/workflow.yml`. Mutation runs on native Linux and retains the complete status
list before enforcing 85%. Content scans use the publication allowlist, staged content, Git
history and exact built archives. The isolated base-wheel smoke covers self-check and growth.

## Actual synthetic comparisons

The [generated report](examples/growth-comparison.json) is recomputed from five executable models.
Preparation with no immediate capacity gain enables reuse: model entry is at time 2 and the
continuation ends at time 3 with task/research capacities 4/4, guaranteed normalized minimum 4/3,
total cost 5 and credits 3 remaining. The restricted comparator upper bound at time 2 is 2/3.
The verification case selects verifier investment; the communication case selects preparation
over expensive dense communication. All-failure and no-advantage cases have no guaranteed entry.
The latter permits a single-process refinement and gives no reward for process or agent count.
The blocker-free ordinary repair planner remains outside the growth objective and receives no
fabricated growth score.

An independent sequence oracle uses elementary arithmetic without planner or transition calls.
It exhausts the small catalogue across budgets. Separate tests compare scalar backward induction
with complete contingent-policy enumeration. Regression categories include all-prefix floors,
shared reservations, queue/debt retention, measurement costs, model/evidence weakening, all
computational limits and witness size, comparator upper bounds, policy tampering, object expiry,
raw-source authority, physical receipt time and stale continuation.

## Scope and remaining risks

Exactness is conditional on the finite catalogue, decision bound, rational piecewise constant
model, observed successor IDs and rectangular uncertainty. The comparison is a worst-case scalar,
not expected-vector dominance or a reliability estimate. The checker verifies witness feasibility;
the submitted tree alone is not an optimality certificate. Budget exhaustion remains unknown.

Real model refinement, measurement construct and coverage validity, source completeness,
independently registered experiments, causal/endogenous attribution, production availability,
penetration review and sustained service evidence remain external obligations. No adapter is
executed, no forecast becomes measured capacity, and existing partial audit findings stay open.
The [paper mapping](growth-research-mapping.md) identifies P1 scope.
