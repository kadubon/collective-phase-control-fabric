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

A stable release additionally requires `release-evidence/vX.Y.Z.json`. The release workflow checks
its exact version and commit bindings and requires passed availability-soak, intended-deployment
restore, load, chaos, independent threat-model, and independent penetration-test evidence. The
manifest is absent until those external activities have actually completed, so the release-assets
and PyPI jobs fail closed even if the publication variable is changed prematurely.

The pending publisher is configured for environment `pypi`. Its GitHub environment reviewer is
`kadubon` with `prevent_self_review=false`. This is self-approval rather than independent release
review. `PYPI_PUBLISH_ENABLED` remains false, and no tag, GitHub Release, or PyPI upload is
permitted before all gates in [release readiness](release-readiness.md) pass.

A pending publisher does not reserve the PyPI project name. The first upload occurs only after the
repository, workflow filename, environment, project name, and OIDC claims match exactly.
