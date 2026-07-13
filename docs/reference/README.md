# Runtime Reference

The files in `generated/` are generated from runtime registries:

- `cli.json` — installed CLI command tree
- `openapi.json` — OpenAPI 3.1 document
- `error-catalog.json` — stable local error and recovery catalog
- `agent-guidance.json` — first-agent claim and command guidance

The schema manifest and individual JSON Schemas are in `schemas/v0.6.0`. Regenerate and verify with:

```text
uv run --frozen python scripts/generate_v6_schemas.py
uv run --frozen python scripts/generate_references.py
uv run --frozen python scripts/check_schemas.py
uv run --frozen python scripts/generate_references.py --check
```
