# Five-Minute Offline Orientation

Run the following after installing the wheel:

```text
cpcf agent explain --json
cpcf self-check --json
cpcf schema list --json
cpcf schema show phase-contract --json
```

These commands perform no network access and require no credentials. `agent explain` states the
claim boundary. `self-check` validates the Python range and runtime schema registry. `schema` reads
the same closed models used by runtime validation.

To verify a portable bundle:

```text
cpcf bundle verify CPCF_BUNDLE --json
cpcf bundle verify CPCF_BUNDLE --trust-policy TRUST_POLICY.json --json
```

Content consistency and distribution authenticity are separate. Without an admitted root
attestation and trust policy, authenticity is `unknown`, even when every object digest matches.
