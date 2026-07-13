# CPCF v0.5 Non-Production Tutorial

This tutorial generates deterministic local fixtures with published private keys. Never reuse its
keys, policy, evidence, results, or trust decisions in another workspace.

```text
python docs/tutorial-v0.5/generate.py --out tutorial-v0.5-assets
cpcf trust genesis-inspect tutorial-v0.5-assets/trust-policy.json --genesis-statement tutorial-v0.5-assets/genesis.json --time-receipt tutorial-v0.5-assets/trusted-time.json --root-fingerprint ROOT_FINGERPRINT_FROM_GENERATOR --json
cpcf workspace init --contract tutorial-v0.5-assets/phase-contract.json --trust-policy tutorial-v0.5-assets/trust-policy.json --genesis-statement tutorial-v0.5-assets/genesis.json --unit-registry tutorial-v0.5-assets/unit-registry.json --root-key-fingerprint ROOT_FINGERPRINT_FROM_GENERATOR --time-receipt tutorial-v0.5-assets/trusted-time.json --out tutorial-v0.5-workspace --json
```

Import each `*-raw.json` before its matching `*-attestation.json`, then run:

```text
cpcf agent onboard --workspace tutorial-v0.5-workspace --compact --json
cpcf execution inspect-risk --workspace tutorial-v0.5-workspace --json
cpcf control next --workspace tutorial-v0.5-workspace --compact --json
```

The tutorial intentionally includes an incomplete operational profile and a forged identity
statement. It demonstrates fail-closed onboarding, role-separated capabilities, unsafe-execution
opt-in, pending projections, and exact recovery commands. It is not evidence of intelligence,
performance, causality, physical organization, or acceleration.
