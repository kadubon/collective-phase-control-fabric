# CPCF v0.4 Evidence-Bound Local Tutorial

This disposable tutorial demonstrates the native v0.4 trust boundary. Its deterministic private
keys are public test material. They must never be used for production trust, distribution, or
measurement claims.

Generate the assets from an installed wheel or source tree:

```text
python generate.py --out assets
```

Read `assets/manifest.json`, independently compare its `root_fingerprint`, and then initialize:

```text
cpcf trust validate assets/trust-policy.json --json
cpcf time inspect assets/trusted-time.json --trust-policy assets/trust-policy.json --json
cpcf workspace init --contract assets/phase-contract.json --trust-policy assets/trust-policy.json --root-key-fingerprint ROOT_FINGERPRINT_FROM_MANIFEST --time-receipt assets/trusted-time.json --out workspace --json
```

Raw records are quarantined until their separately signed typed attestations are imported:

```text
cpcf source import assets/state-raw.json --workspace workspace --source-system tutorial --schema-ref typed-record@0.4.0 --apply --json
cpcf attestation import assets/state-attestation.json --workspace workspace --apply --json
cpcf source import assets/suite-raw.json --workspace workspace --source-system tutorial --schema-ref typed-record@0.4.0 --apply --json
cpcf attestation import assets/suite-attestation.json --workspace workspace --apply --json
cpcf doctor --workspace workspace --json
cpcf science audit --workspace workspace --compact --json
cpcf perturbation replay --workspace workspace --suite suite:tutorial --json
```

The forged independence file must fail because an unpinned attacker signed it while claiming the
source key identifier:

```text
cpcf attestation inspect assets/forged-independence.json --trust-policy assets/trust-policy.json --json
```

The local action uses the generator's digest-pinned Python executable and a local adapter outside
the workspace. Import its raw record and attestation, then plan and execute one action:

```text
cpcf source import assets/action-raw.json --workspace workspace --source-system tutorial --schema-ref typed-record@0.4.0 --apply --json
cpcf attestation import assets/action-attestation.json --workspace workspace --apply --json
cpcf control next --workspace workspace --compact --json
cpcf control run --workspace workspace action:tutorial --apply --json
```

For the trial path, first content-address the committed dataset and analysis specification, then
import the externally registered protocol. The supported and inconclusive results are alternatives
for the same unique primary result and therefore must be tested in separate copied workspaces.

```text
cpcf source import assets/dataset.json --workspace workspace --source-system tutorial --schema-ref dataset-record@0.4.0 --apply --json
cpcf source import assets/analysis-spec.json --workspace workspace --source-system tutorial --schema-ref analysis-executable-record@0.4.0 --apply --json
cpcf trial protocol-inspect assets/protocol.json --registration-receipt assets/registration.json --workspace workspace --json
cpcf trial protocol-import assets/protocol.json --registration-receipt assets/registration.json --workspace workspace --apply --json
cpcf trial inspect assets/result-inconclusive.json --workspace workspace --json
cpcf trial import assets/result-inconclusive.json --workspace workspace --apply --json
```

The example establishes only local conformance. CPCF does not certify the statistical method,
causality, intelligence, physical chemistry, or a collective-superintelligence phase.
