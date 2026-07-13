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
| `cpcf auth login --json` | no | inspect token boundary | OIDC identity for later remote use |
| `cpcf workspace create ID --json` | yes | create workspace | bearer token and idempotency key |
| `cpcf workspace status ID --json` | yes | inspect workspace | workspace read permission |
| `cpcf audit start ID --generation DIGEST --json` | yes | queue audit | workspace mutation permission and generation match |
| `cpcf audit status JOB_ID --json` | yes | inspect immutable job | tenant job read permission |
| `cpcf agent onboard --workspace ID --json` | yes | inspect live onboarding blockers | workspace read permission |
| `cpcf legacy inspect ...` | local subprocess | read-only legacy inspection | none; v0.1–v0.5 remain non-executable |

Trust admission, projection approval, runner leasing, coordination, trials, interventions, and
repairs are modelled in the core but do not yet have complete authoritative v0.6 CLI/API workflows.
They remain stable-release blockers and are not advertised as installed commands.
