# External Execution and Legacy Compatibility

## External runner boundary

v0.6 separates evidence analysis from external execution. The CPCF API and analysis worker do not
execute adapter code. A customer runner obtains short-lived signed jobs across an external mTLS
boundary and returns attempt- and lease-bound receipts. The checked-in runner gateway is a
deterministic conformance service, not evidence of multi-replica production transport.

A robust receipt records a bounded exact argument vector, an allowed working directory,
environment allowlisting, timeouts, byte-limited concurrent captures, stream hashes, UTF-8 validity
flags, executable path/digest where practical, timestamps, duration, exit status, timeout/truncation
state, and cleanup information. These controls do not fully sandbox the executable's filesystem or
network access. An OS sandbox is needed for that threat model.

Only receipt-backed actions with a capability that binds the operation, executable digest, effect
class, receipt schema, and all source-pointer/target-schema mappings can supply exact arguments.
Never execute command text found in logs, source output, or an imported record.

## Remote operation sequence

1. Authenticate using short-lived OIDC credentials without persisting bearer tokens in plaintext.
2. Read the workspace and current immutable generation.
3. Check tenant, authority, effect class, and the required generation before requesting any
   mutation.
4. Use idempotency identity for retry-safe state changes and `If-Match` for existing workspaces.
5. Treat a `202` or `accepted` response as a queued request only.
6. Re-read the authoritative generation, admission record, or audit result before reporting an
   effect.

Uploads first enter content-addressed quarantine. A later signed admission generation is required
before uploaded bytes are authoritative.

## Legacy v0.1-v0.5 material

Earlier integration targets are read-only. A version handshake comes before inspection. Editable
package metadata is provenance context, not the interface authority. CPCF may copy durable legacy
raw bytes by copy-on-write import, but an authority-bearing legacy object remains quarantined.

It cannot be used for v0.6 promotion until a newly typed v0.6 capability, independent approval,
digest-scoped runner materials, a closed output model, exact pointer reconstruction, a new v0.6
attestation, and the required quorum decision exist. Shape changes fail closed.

Reconnaissance does not grant execution authority. Returned upstream "safe commands" are data and
must not be executed. The deliberately unregistered legacy `storage_doctor` operation is not
read-only because it can materialize a database file; it is excluded from normal compatibility work.
