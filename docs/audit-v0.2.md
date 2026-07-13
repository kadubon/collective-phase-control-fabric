# CPCF v0.2 Adversarial Audit

This audit records the defects that required the v0.3 execution boundary. “Closed” means the v0.3
path has a regression test; it does not retroactively make a v0.2 workspace executable.

| Finding | Severity | v0.2 defect | v0.3 correction |
|---|---:|---|---|
| TRUST-001 | critical | Runtime receipt coordinates were hard-coded true. | Reconstruct every coordinate and pointer from raw bytes on every read. |
| TRUST-002 | critical | A signature could authenticate its own carried public key. | Pin one Ed25519 key per principal in the generation trust policy. |
| TRUST-003 | critical | Legacy certificate Booleans could establish compatibility. | Legacy Booleans are inspectable but non-authoritative. |
| TRUST-004 | critical | Cached receipt fields could influence ordinary inspection. | Cached validation is diagnostic only. |
| TRUST-005 | critical | Projected digests were not always reconstructed from raw pointers. | Re-resolve exact RFC 6901 pointers and compare canonical bytes and digests. |
| STORE-001 | critical | Multi-file updates could expose partial state. | Commit immutable generations by one atomic `CURRENT` replacement. |
| EXEC-001 | critical | JSON could declare success independently of process status. | Nonzero exit, timeout, truncation, malformed schema, or binding mismatch selects failure. |
| EXEC-002 | high | Adapters ran in the workspace directory. | Run in an unrelated invocation directory with a minimal environment and detect workspace mutation. |
| SCHEMA-001 | high | Native schemas accepted undeclared authority-bearing fields. | Close v0.3 schemas and isolate ignored reverse-DNS extensions. |
| PLAN-001 | critical | Multi-step search added success forecasts without branch state. | Build bounded AND–OR trees over all four recomputed abstract outcomes. |
| PLAN-002 | high | Resource coordinates were absent from v0.2 dominance. | Compare guaranteed resource lower changes without unit mixing. |
| SCI-001 | critical | Witness reference presence could substitute for live provenance. | Bind all scientific witnesses to one network, targets, transformations, and live source records. |
| SCI-002 | high | Witnesses could invent initial balances and food. | Derive markings and food from receipt-backed initial state. |
| SCI-003 | high | Catalytic closure was not target-organization bound. | Require generalized and generative RAF closure over the exact organization set. |
| SCI-004 | high | Cycle enumeration was incomplete and potentially unbounded. | Verify exact per-transformation dual resource-potential inequalities. |
| SCI-005 | high | Persistence did not establish siphon or rate feasibility. | Add bounded-exact siphons, live coverage, and exact feasible flux intervals. |
| SCI-006 | high | Empty perturbations could allow L5. | Require every referenced suite, at least one case, and explicit acceptance criteria. |
| COLL-001 | high | Exposure did not reduce independence status. | Remove pre-commit-exposed domains and merge shared infrastructure/correlation domains. |
| UX-001 | medium | First-use commands referenced absent files. | Provide a non-executable decision scaffold and workspace-aware onboarding. |
| QA-001 | medium | Statement coverage hid untested branches. | Enable branch coverage and add v0.3 adversarial and property tests. |

The machine-readable counterpart is `audit/findings.json`.
