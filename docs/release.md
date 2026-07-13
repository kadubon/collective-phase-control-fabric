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

Until an independent reviewer is configured and the PyPI pending publisher is changed from
environment “Any” to `pypi`, `PYPI_PUBLISH_ENABLED` remains false. No tag, GitHub Release, or PyPI
upload is permitted before all gates in [release readiness](release-readiness.md) pass.

A pending publisher does not reserve the PyPI project name. The first upload occurs only after the
repository, workflow filename, environment, project name, and OIDC claims match exactly.
