# Explicit mutation qualification exception for CPCF 1.0.0

**Mutation qualification is waived, not passed. No complete passing mutation score
is available for this release candidate.**

On 2026-09-12 the repository owner explicitly authorized merging without completed
mutation tests, then extended that authorization to the GitHub release and PyPI
publication. The accompanying assumption that local mutation testing had already
completed was corrected: the native run was still incomplete. Its partial results
are not a passing score or release assurance.

The first expanded CI run, `34668423252`, reached the 300-minute limit in all five
mutation jobs. Its aggregate correctly failed. The catalogue contains 17,581 names,
including all configured modules and required control methods. Twenty disjoint
execution parts were subsequently introduced, preserving all five logical shards,
full catalogue checking and the 85% score floor. No interrupted or incomplete run
is recorded as successful.

The owner-authorized administrator exception covers the missing independent PR
review and mutation qualification for **1.0.0 only**. Other required platform,
integration, coverage, security and publication checks must pass. The protected
PyPI environment and OIDC trusted publisher remain unchanged.

The release workflow permits this exception only for a `release` event on
`v1.0.0` with repository variable `CPCF_MUTATION_EXCEPTION_VERSION=1.0.0`.
Mutation jobs are visibly **skipped**; a separate waiver job records the missing
qualification. Asset upload and PyPI publication still require successful build,
provenance, Beta classification and the explicit waiver record. A failed mutation
job cannot be converted into this skipped-job exception. Verification-only
dispatches, other versions, and normal CI retain the complete mutation gate.
The exception variable is removed after the release attempt.

This is a reduction in software assurance accepted by the owner, not equivalent
mutation evidence. Future work must complete full mutation qualification and
address survivors under the unchanged 85% floor. Beta classification, the lack of
external empirical acceleration evidence and all scientific claim boundaries
remain unchanged.
