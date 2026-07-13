# Security and Publication Hygiene

Security authority comes from admitted evidence and role separation, not from labels or cached
validation results. The production server stores no private signing keys. Tenant authorization and
evidence-principal identity are separate domains.

Before any commit intended for publication:

```text
uv run --frozen python scripts/check_publication_hygiene.py --source-tree
uv run --frozen gitleaks git --redact --config .gitleaks.toml
git diff --cached --name-only
uv run --frozen python scripts/check_publication_hygiene.py --staged
git diff --cached --stat
git diff --cached
```

The initial stage must be built from `publication-files.txt`, never `git add .`. The checker rejects
home-directory paths, private keys, known token formats, credentialed connection strings,
certificates, key stores, local databases, caches, coverage output, build directories, oversized
files, and paths outside the allowlist. It reports only rule names and locations, not matched values.

Wheel and source distributions are scanned again:

```text
uv build
uv run --frozen python scripts/check_publication_hygiene.py --archive dist/FILE.whl --archive dist/FILE.tar.gz
```

Anchored allowlists are limited to documented disposable CI values. Broad path or regex exclusions
are prohibited. See [SECURITY.md](../SECURITY.md) for private vulnerability reporting.
