# CPCF 1.0.0 requirement and verification matrix

Baseline: released 0.7.0, commit `0afced595da264c500b527533321aa50d73fc4bb`.
This is an implementation tracking record, not a claim that pending work passed.

| Requirement | Intended code and tests | Status |
| --- | --- | --- |
| M8: fixed parameter, correlated support and visible observations | Additive epistemic documents; primitive-ledger support update; observation-policy search and independent checker; tiny policy oracle | Implemented; qualification in progress |
| M8: entry, continuation, frontier and evidence | Common visible stopping; per-hypothesis lineage; fresh existing evidence validation; replay/replan tests | Implemented; qualification in progress |
| M9: information-use and net sensing comparisons | Matched physical probe with masked channel; no-probe class; exact reoptimization; refinement and adverse probe tests | Implemented; qualification in progress |
| M10: typed bounded workflow synthesis | Primitive IR grammar, prefix unfolding checker, scoped certificates; flattening oracle | Implemented; qualification in progress |
| M10: copy-on-write catalogue revisions | Checked candidate proposals, carried obligations and costs, bounded model-only reuse; integrated installed example | Implemented; qualification in progress |
| Maintained 1.0 public API | Explicit facade and JSON/CLI contract; compatibility and installed-wheel tests | Implemented; qualification in progress |
| Released compatibility | Preserve all 55 existing native schema identities and 0.6.1/0.7.0 golden encodings | Released 55-schema and original golden regressions passed; final rerun pending |
| Assurance gates | Full supported matrix, per-subsystem coverage, expanded complete mutation catalogue, security and publication hygiene | Tests and exploratory coverage run; final qualification and mutation pending |
| Docs and actual Wiki | Canonical guides, generated references, skill and separate Wiki commit | Guides and skill updated; nine Wiki candidate pages pushed and remote commit verified |
| Release and public-index installation | Required checks, owner-authorized merge, exact tag/run/artifacts, existing OIDC publisher, external clean installation | Pending |

No external empirical acceleration experiment is available or required. Synthetic model
checking does not establish empirical validity, admission, authority or operational assurance.
The package remains Beta; 1.0.0 concerns its documented maintained public software API.

Current repository policy requires one approval of the latest push and 13 checks. The
authenticated repository owner cannot provide an independent approval of their own PR.
The owner subsequently authorized an administrator review exception specifically for
the 1.0.0 PR, conditional on every required check passing. This is not independent
review and does not authorize bypassing checks or publication environment approval.
The merge and its exact check results remain pending.

Detailed qualification status and metric definitions: [1.0 validation](validation-1.0.md).
