# Remote Workspace Use

Remote commands use `CPCF_API_URL` and a short-lived bearer token in `CPCF_TOKEN`. The CLI does not
store credentials.

```text
set CPCF_API_URL=https://cpcf.example.org
set CPCF_TOKEN=OIDC_ACCESS_TOKEN
cpcf workspace create WORKSPACE --json
cpcf workspace status WORKSPACE --json
cpcf audit start WORKSPACE --generation sha256:GENERATION --json
cpcf audit status JOB_ID --json
cpcf agent onboard --workspace WORKSPACE --json
```

`workspace create` and `audit start` are state-changing. The CLI supplies an idempotency key; callers
should set `CPCF_IDEMPOTENCY_KEY` when retries must share one identity. Existing-generation
mutations require `If-Match` and fail on a stale generation.

The current API surface is deliberately narrow. Trust admission, projection approval,
coordination, trials, runner transport, and complete live onboarding aggregation remain release
blockers until their authoritative endpoints and integration tests are present.
