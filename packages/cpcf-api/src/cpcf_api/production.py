# SPDX-License-Identifier: Apache-2.0
"""Production application wiring; missing authority configuration fails at startup."""

from __future__ import annotations

import importlib
import os

from cpcf_api.app import create_app
from cpcf_api.auth import OidcAuthenticator
from cpcf_api.db import PostgresBackend, make_engine
from cpcf_api.object_store import S3ObjectStore


class _LazyS3Client:
    """Defer credential discovery and network configuration until service startup."""

    def __init__(self) -> None:
        self._client: object | None = None

    def __getattr__(self, name: str) -> object:
        if self._client is None:
            self._client = importlib.import_module("boto3").client(
                "s3",
                endpoint_url=os.environ.get("CPCF_OBJECT_ENDPOINT"),
                region_name=os.environ.get("CPCF_OBJECT_REGION"),
            )
        return getattr(self._client, name)


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
object_store = S3ObjectStore(_LazyS3Client(), _required("CPCF_OBJECT_BUCKET"))
app = create_app(
    backend=PostgresBackend(engine),
    authenticator=authenticator,
    object_store=object_store,
)
