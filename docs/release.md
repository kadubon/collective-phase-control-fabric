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

The 0.6 series is published with the package classifier `Development Status :: 4 - Beta`.
The release workflow uses the explicit `beta` publication class, which permits OSS package
distribution without treating absent external evidence as satisfied. A Beta package release is not
an operational-assurance decision.

Operational assurance separately requires `release-evidence/vX.Y.Z.json`. The strict default mode
checks exact version and commit bindings and requires passed availability-soak,
intended-deployment restore, load, chaos, independent threat-model, and independent
penetration-test evidence. The manifest remains absent until those activities have actually
completed.

The pending publisher is configured for environment `pypi`. Its GitHub environment reviewer is
`kadubon` with `prevent_self_review=false`. This is self-approval rather than independent release
review. It can authorize Beta package distribution, but it cannot satisfy the independent
operational-review requirements in [release readiness](release-readiness.md).

A pending publisher does not reserve the PyPI project name. The first upload occurs only after the
repository, workflow filename, environment, project name, and OIDC claims match exactly.
