# SPDX-License-Identifier: Apache-2.0
"""OIDC authentication and deny-by-default operation authorization."""

from __future__ import annotations

from typing import Protocol

import jwt
from pydantic import BaseModel, ConfigDict, Field


class PrincipalContext(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    subject: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    roles: frozenset[str] = Field(max_length=64)


class Authenticator(Protocol):
    async def authenticate(self, token: str) -> PrincipalContext: ...


class OidcAuthenticator:
    """Strict OIDC token verifier with explicit issuer, audience, and algorithms."""

    def __init__(
        self,
        issuer: str,
        audience: str,
        jwks_url: str,
        *,
        maximum_token_lifetime_seconds: int = 3600,
    ) -> None:
        if not issuer.startswith("https://") or not jwks_url.startswith("https://"):
            raise ValueError("production OIDC endpoints must use HTTPS")
        if not 60 <= maximum_token_lifetime_seconds <= 86_400:
            raise ValueError("OIDC maximum token lifetime must be between 60 and 86400 seconds")
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.maximum_token_lifetime_seconds = maximum_token_lifetime_seconds
        self.jwks = jwt.PyJWKClient(jwks_url, cache_keys=True)

    async def authenticate(self, token: str) -> PrincipalContext:
        key = self.jwks.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            key.key,
            algorithms=["RS256", "ES256", "EdDSA"],
            audience=self.audience,
            issuer=self.issuer,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
        tenant_id = claims.get("tenant_id")
        roles = claims.get("roles", [])
        if not isinstance(tenant_id, str) or not isinstance(roles, list):
            raise jwt.InvalidTokenError("tenant_id and roles claims are required")
        issued_at = claims.get("iat")
        expires_at = claims.get("exp")
        if not isinstance(issued_at, int | float) or not isinstance(expires_at, int | float):
            raise jwt.InvalidTokenError("numeric iat and exp claims are required")
        if expires_at <= issued_at:
            raise jwt.InvalidTokenError("token expiry must follow issuance")
        if expires_at - issued_at > self.maximum_token_lifetime_seconds:
            raise jwt.InvalidTokenError("token lifetime exceeds configured maximum")
        return PrincipalContext(
            subject=str(claims["sub"]),
            tenant_id=tenant_id,
            roles=frozenset(item for item in roles if isinstance(item, str)),
        )


ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "tenant_admin": frozenset(
        {
            "workspace:create",
            "workspace:read",
            "object:import",
            "analysis:start",
            "action:dispatch",
            "projection:approve",
            "coordination:write",
            "trial:write",
        }
    ),
    "auditor": frozenset({"workspace:read", "analysis:start"}),
    "planner": frozenset({"workspace:read", "analysis:start", "action:dispatch"}),
    "projection_verifier": frozenset({"workspace:read", "projection:approve"}),
    "trial_registrar": frozenset({"workspace:read", "trial:write"}),
    "runner": frozenset({"runner:claim", "runner:submit"}),
}


def authorize(principal: PrincipalContext, operation: str, tenant_id: str) -> None:
    if principal.tenant_id != tenant_id:
        raise PermissionError("cross_tenant_access_denied")
    permissions = set().union(
        *(ROLE_PERMISSIONS.get(role, frozenset()) for role in principal.roles)
    )
    if operation not in permissions:
        raise PermissionError("operation_denied_by_default")
