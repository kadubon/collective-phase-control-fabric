# CPCF v0.3 Adversarial Audit

This audit defines the incompatibility boundary introduced by CPCF v0.4. A closed finding means
that the identified v0.3 exploit has a concrete v0.4 correction and named regression test. It does
not imply that the implementation is free from undiscovered defects.

## Verdict

The v0.3 kernel was useful for deterministic research, but its signatures did not protect all
authority-bearing metadata, its semantic nodes were not uniformly principal-attested, and its
perturbation and contingent-control analyses did not carry the complete operational state. It is
therefore inspection-only under v0.4. Migration is copy-on-write and quarantines every legacy
signature, projection, witness, certificate, action, and receipt.

## Closed defect classes

| Class | v0.3 failure | v0.4 control |
|---|---|---|
| Trust | Protected metadata could be rewritten. | The complete protected header and canonical payload digest are signed. |
| Time | Local or stale time could establish validity. | Promotion requires a subject-bound external trusted-time receipt. |
| Provenance | A network signer could assign other principals and roles. | Each semantic object is a source-matched typed principal attestation. |
| Storage | Manifests did not prove full transitive closure. | A typed ledger covers all authority-bearing objects and CAS references. |
| Execution | Limits and selectors were partly hard-coded. | Signed capabilities bind limits, selectors, exit mapping, and environment. |
| Science | Perturbation replay omitted operational dimensions. | Baseline and perturbations use one ten-stage audit kernel. |
| Planning | Candidate order and partial state could change selection. | Full filtering precedes the cap; every branch propagates the complete abstract state. |
| Trials | Preregistration and artifacts were underbound. | External registration, CAS dataset/executable, amendments, and a unique primary result are mandatory. |
| Coordination | Labels and missing exposure data could imply independence. | Only signed commitments and trusted observations count; missing exposure data remains unknown. |
| Distribution | Internal consistency could be mistaken for authenticity. | Unsigned bundles report authenticity unknown; an optional signed root is verified separately. |

The complete record, including severity, exploit, affected claim, correction, regression test, and
closure state, is [findings-v0.3.json](findings-v0.3.json).

The semantic v0.3 findings are closed by named tests. `V4-QA-001` remains open because the overall
90% coverage gate passes while several individual v0.4 modules remain below the plan's 95% target.
This is a verification-completeness limitation, not evidence that a known semantic exploit remains
promoting.

## Claim boundary

CPCF v0.4 reports a three-valued operational organization profile and separately validates
externally preregistered acceleration evidence. It does not infer a collective-superintelligence
phase, statistical causality, thermodynamic equivalence, general controllability, or an operating
system sandbox guarantee.
