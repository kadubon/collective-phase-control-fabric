# Portability

The single `collective-phase-control-fabric` distribution supports standard CPython 3.12–3.14 on
Windows and Linux. The base installation provides offline core analysis, CLI orientation, schemas,
bundle verification, and runner protocol models. Server, worker, runner, solver, and KMS clients are
extras.

The wheel is platform-independent Python. Optional integrations can impose their own platform wheel
constraints. Linux amd64/arm64 OCI images are a release target but are not a local wheel property.
macOS, free-threaded Python, and multi-region operation are not claimed without corresponding CI and
operational evidence.

Portable bundles contain immutable content and digests. An unsigned bundle establishes content
consistency only; distribution authenticity remains unknown.
