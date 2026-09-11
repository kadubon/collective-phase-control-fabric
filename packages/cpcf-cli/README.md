# CPCF CLI

English, machine-readable command-line client for the CPCF v0.6 control plane, plus explicitly
read-only inspection of v0.1-v0.5 workspaces. The client reads bearer tokens from the environment
and does not persist credentials.

The installed base wheel also provides offline `growth` inspection, planning,
independent checking and observation replay. Opt in with `--epistemic` for fixed
models; `information-value`, `synthesize`, `check-composition`, `catalogue-propose`
and `catalogue-replan --model-only` cover finite procedural reuse. See the
[public API](../../docs/public-api.md) and
[integrated example](../../docs/epistemic-growth-control.md). These commands do
not require a server or model provider and do not grant execution authority.
