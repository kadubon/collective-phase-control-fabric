# Installation

## Consumer installation

CPCF supports standard CPython 3.12–3.14 on Windows and Linux. Python 3.14.0 and 3.14.1 are
excluded.

```text
pip install collective-phase-control-fabric
pipx install collective-phase-control-fabric
pip install "collective-phase-control-fabric[server,solver]"
```

The default installation is offline-capable. Extras are:

| Extra | Adds |
|---|---|
| `server` | FastAPI, PostgreSQL, OIDC, OpenTelemetry, and object-store dependencies |
| `worker` | trusted asynchronous analysis-worker dependencies |
| `runner` | HTTP/2 client support for runner implementations |
| `solver` | bounded Z3 analysis |
| `aws-kms` | AWS KMS client |
| `gcp-kms` | Google Cloud KMS client |
| `azure-kms` | Azure Key Vault client |
| `pkcs11` | PKCS#11 client |
| `all` | every optional integration |

Optional service entry points report an exact installation command when their extra is absent.

## Contributor installation

Contributor and release environments use only the checked-in `uv.lock`:

```text
uv sync --frozen --all-extras --group dev --group security
uv run --frozen cpcf self-check --json
```

Do not replace frozen `uv` resolution with exported pip requirements when reporting repository
verification results.
