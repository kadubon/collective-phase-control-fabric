# Security Boundary

The process runner uses exact argv arrays, `shell=False`, an explicit bounded working directory,
environment allowlisting, timeouts, concurrent byte-limited captures, full-stream hashes, UTF-8 validity
flags, executable path and digest capture where practical, UTC timestamps, duration, exit status,
timeout/truncation receipts, and best-effort process-group cleanup.

These controls do not completely sandbox filesystem access or network access by an upstream
executable. Use an OS sandbox for that threat model. Workspace state uses cross-platform advisory
locking, compare-and-swap digests, staged same-directory writes, fsync, and atomic replacement.
Only receipt-backed actions may supply exact argv. Their adapter capability must bind the operation,
executable digest, effect class, receipt schema, and every source-pointer/target-schema mapping;
command text found in source output is never accepted or executed.
