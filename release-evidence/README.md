# Stable Release Evidence

This directory intentionally contains no versioned operational-evidence manifest. A file named
`vX.Y.Z.json` may be added only after the external activities it references have completed.
`scripts/check_external_release_evidence.py` requires exact version and Git commit bindings,
content digests, a 30-day availability soak, an intended-deployment restore, load and chaos
profiles, independent threat-model review, and an independent penetration test with no open
blocking findings.

The validator is strict by default. Its explicit `--publication-class beta` mode permits package
distribution while reporting that operational evidence is unavailable. This mode does not mark
any external gate passed and cannot support an operational-assurance claim.

The manifest records evidence digests and non-secret summaries. It must not contain reports,
credentials, customer data, private endpoints, or evidence payloads. A passing manifest is a
release input, not proof that undiscovered defects are impossible.
