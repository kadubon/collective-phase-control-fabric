# Runtime Reference

The files in `generated/` are generated from runtime registries:

- `cli.json` — installed CLI command tree
- `openapi.json` — OpenAPI 3.1 document
- `error-catalog.json` — stable local error and recovery catalog
- `agent-guidance.json` — first-agent claim and command guidance

Package 0.7.0 adds `growth-capability-frontier`, `growth-frontier-plan` and
`growth-frontier-assessment`; the preceding 52 schema identities remain unchanged. CLI frontier
options and error codes are runtime-derived. OpenAPI package version is separate from protocol
identity `cpcf.io/v0.6`.

The schema manifest and individual JSON Schemas are in `schemas/v0.6.0`. Regenerate and verify with:

```text
uv run --frozen python scripts/generate_v6_schemas.py
uv run --frozen python scripts/generate_references.py
uv run --frozen python scripts/check_schemas.py
uv run --frozen python scripts/generate_references.py --check
```
