# CPCF v0.3 Signed Local Tutorial

This tutorial is an orientation and adversarial conformance example. It is not evidence of
collective intelligence, causal acceleration, or a physical phase. Its private keys are public test
material and must never be trusted outside a disposable tutorial workspace.

From an installed wheel, locate this directory under
`collective_phase_control_fabric/data/docs/tutorial-v0.3`, copy it to a writable directory, and run:

```text
python generate.py --out assets
cpcf workspace init --contract assets/phase-contract.json --trust-policy assets/trust-policy.json --out workspace --json
cpcf agent onboard --workspace workspace --compact --json
cpcf source import assets/transformation-network.json --workspace workspace --source-system tutorial --schema-ref transformation-network@0.3.0 --apply --json
cpcf source import assets/state-marking.json --workspace workspace --source-system tutorial --schema-ref state-marking@0.3.0 --apply --json
cpcf source import assets/branch-effect-contract.json --workspace workspace --source-system tutorial --schema-ref branch-effect-contract@0.3.0 --apply --json
cpcf source import assets/adapter-capability.json --workspace workspace --source-system tutorial --schema-ref adapter-capability@0.3.0 --apply --json
cpcf source import assets/action.json --workspace workspace --source-system tutorial --schema-ref action@0.3.0 --apply --json
cpcf doctor --workspace workspace --json
cpcf control next --workspace workspace --compact --json
cpcf control run --workspace workspace action:tutorial --apply --json
```

The action has success, partial, failure, and timeout abstract effects. The local adapter emits the
success selector in this walkthrough. Process status remains authoritative, and the promoted
observation is reconstructed from `/observation` in the raw adapter output.

The spoof must fail pinned-key verification:

```text
cpcf source inspect assets/spoofed-state-marking.json --trust-policy assets/trust-policy.json --source-system tutorial --schema-ref state-marking@0.3.0 --json
```

The protocol is imported before either result. The inconclusive and supported files are alternative
results for the same synthetic protocol; use separate copied workspaces when comparing them.

```text
cpcf source import assets/measurement-protocol.json --workspace workspace --source-system tutorial --schema-ref measurement-protocol@0.3.0 --apply --json
cpcf trial inspect assets/result-inconclusive.json --workspace workspace --json
cpcf trial import assets/result-inconclusive.json --workspace workspace --apply --json
cpcf science audit --workspace workspace --compact --json
```

The generated `manifest.json` records every file digest, the pinned public key, the adapter digest,
and expected outcome class. Source import creates the authoritative envelope and projection receipt
inside the immutable workspace generation; no static tutorial receipt is treated as authority.
