# SPDX-License-Identifier: Apache-2.0
"""Production application wiring; missing authority configuration fails at startup."""

from __future__ import annotations

import os

from cpcf_api.app import create_app
from cpcf_api.auth import OidcAuthenticator
from cpcf_api.db import PostgresBackend, make_engine


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


authenticator = OidcAuthenticator(
    _required("CPCF_OIDC_ISSUER"),
    _required("CPCF_OIDC_AUDIENCE"),
    _required("CPCF_OIDC_JWKS_URL"),
)

engine = make_engine(_required("CPCF_DATABASE_URL"))
_required("CPCF_OBJECT_BUCKET")
app = create_app(backend=PostgresBackend(engine), authenticator=authenticator)
