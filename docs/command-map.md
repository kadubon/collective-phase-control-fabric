# v0.6 Command Map

Only commands present in the installed `cpcf` parser are listed here. The machine-readable command
tree is generated at `docs/reference/generated/cli.json`.

| Command | Network | Effect | Authority |
|---|---:|---|---|
| `cpcf agent explain --json` | no | inspect claim boundary and safe commands | none |
| `cpcf self-check --json` | no | validate installed core and schema registry | none |
| `cpcf schema list --json` | no | list installed closed schemas | none |
| `cpcf schema show KIND --json` | no | show installed schema | none |
| `cpcf bundle verify BUNDLE --json` | no | verify content digests | none |
| `cpcf bundle verify BUNDLE --trust-policy POLICY --json` | no | verify content and supported root attestation | admitted trust policy |
| `cpcf auth login --json` | yes | OIDC device login; store access token only in OS keyring | OIDC identity and secure keyring backend |
| `cpcf workspace create ID --root-spki-fingerprint DIGEST --genesis-envelope-fingerprint DIGEST --json` | yes | create workspace with both out-of-band genesis pins | bearer token and idempotency key |
| `cpcf workspace status ID --json` | yes | inspect workspace | workspace read permission |
| `cpcf object upload ID PATH --generation DIGEST --json` | yes | conditionally upload digest-scoped CAS bytes; authority remains quarantined | object import permission, idempotency key, and generation match |
| `cpcf object admit ID --generation DIGEST --digest DIGEST --json` | yes | queue signed object admission | object import permission and generation match |
| `cpcf attestation admit ID --generation DIGEST --digest DIGEST --json` | yes | queue typed attestation admission | object import permission and generation match |
| `cpcf trust status|update ...` | yes | inspect trust or queue a role-separated update | workspace read, or root/auditor/time authority |
| `cpcf time status|update ...` | yes | inspect time or queue a trusted receipt | workspace read, or timestamp authority |
| `cpcf audit start ID --generation DIGEST --json` | yes | queue audit | workspace mutation permission and generation match |
| `cpcf audit status JOB_ID --json` | yes | inspect immutable job | tenant job read permission |
| `cpcf perturbation replay ID --generation DIGEST [--scenario ID] --json` | yes | queue reduced-snapshot replay | auditor and generation match |
| `cpcf intervention analyze ID --generation DIGEST --json` | yes | queue bounded intervention analysis | planner/auditor and generation match |
| `cpcf action dispatch ID --generation DIGEST --digest ACTION --json` | yes | queue one signed action | action dispatcher and generation match |
| `cpcf projection pending|approve ...` | yes | inspect pending projections or queue independent approval | workspace read, or projection verifier |
| `cpcf coordination init|commit|reveal|route|terminate|status ...` | yes | inspect or queue signed session transitions | coordination participant and generation match |
| `cpcf trial protocol-import|amendment-import|result-import|status ...` | yes | inspect or queue trial evidence admission | registered trial roles and generation match |
| `cpcf quarantine list|resolve ...` | yes | inspect or queue a quarantine change | workspace read, or tenant administrator |
| `cpcf repair list|show|run ...` | yes | inspect typed repairs or queue a bound repair action | workspace read, or tenant administrator |
| `cpcf agent onboard --workspace ID --json` | yes | inspect live onboarding blockers | workspace read permission |
| `cpcf legacy inspect ...` | local subprocess | read-only legacy inspection | none; v0.1–v0.5 remain non-executable |

All mutation commands above return queued work. Their presence does not establish that the
PostgreSQL worker completed authoritative admission; end-to-end admission and multi-replica runner
evidence remain stable-release blockers.
