# SPDX-License-Identifier: Apache-2.0
"""CPCF API process entrypoint."""

from __future__ import annotations

import os
import sys


def main() -> int:
    try:
        import uvicorn
    except ModuleNotFoundError:
        print(
            "The server extra is required. Install it with: "
            'pip install "collective-phase-control-fabric[server]"',
            file=sys.stderr,
        )
        return 2

    if not os.environ.get("CPCF_DATABASE_URL"):
        print("CPCF_DATABASE_URL is required for the API service", file=sys.stderr)
        return 2
    if not os.environ.get("CPCF_OIDC_ISSUER"):
        print("CPCF_OIDC_ISSUER is required for the API service", file=sys.stderr)
        return 2
    uvicorn.run(
        "cpcf_api.production:app",
        host=os.environ.get("CPCF_BIND_HOST", "127.0.0.1"),
        port=int(os.environ.get("CPCF_BIND_PORT", "8080")),
        proxy_headers=False,
        server_header=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
