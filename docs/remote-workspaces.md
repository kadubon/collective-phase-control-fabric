# Remote Workspace Use

Remote commands use `CPCF_API_URL` and a short-lived OIDC bearer token. `cpcf auth login` uses the
OIDC device flow and stores the access token only in an available OS keyring. If no secure keyring
backend is available, login fails with `secure_credential_store_unavailable`; CPCF never falls back
to a plaintext token file. `CPCF_TOKEN` remains a non-persistent environment fallback.

```text
set CPCF_API_URL=https://cpcf.example.org
set CPCF_OIDC_DEVICE_AUTHORIZATION_ENDPOINT=https://identity.example.org/oauth/device
set CPCF_OIDC_TOKEN_ENDPOINT=https://identity.example.org/oauth/token
set CPCF_OIDC_CLIENT_ID=cpcf-cli
cpcf auth login --json
cpcf workspace create WORKSPACE --root-spki-fingerprint sha256:ROOT_SPKI_SHA256 --genesis-envelope-fingerprint sha256:GENESIS_ENVELOPE_SHA256 --json
cpcf object upload WORKSPACE SIGNED_STATEMENT.json --generation sha256:GENERATION --json
cpcf object admit WORKSPACE --generation sha256:GENERATION --digest sha256:SIGNED_STATEMENT --json
cpcf workspace status WORKSPACE --json
cpcf audit start WORKSPACE --generation sha256:GENERATION --json
cpcf audit status JOB_ID --json
cpcf agent onboard --workspace WORKSPACE --json
```

`workspace create`, `object upload`, and `audit start` are state-changing. Uploaded CAS bytes remain
quarantined and non-authoritative until a later signed admission generation. The CLI supplies an idempotency key; callers
should set `CPCF_IDEMPOTENCY_KEY` when retries must share one identity. Existing-generation
mutations require `If-Match` and fail on a stale generation.

The API and CLI expose generation-bound queued workflows for object admission, trust and time,
perturbations, interventions, actions, projection approval, coordination, trials, quarantine, and
repairs. A `202` response means only that immutable work was queued; it never means that evidence
was admitted or a generation advanced. The worker must re-load the authoritative snapshot and
validate the operation before any effect.

A separate runner-gateway contract covers claim, heartbeat, bounded artifact upload, and
completion. Its checked-in implementation remains a deterministic conformance service, not a
multi-replica production transport. Production persistence and end-to-end admission-worker
evidence remain stable-release blockers.
