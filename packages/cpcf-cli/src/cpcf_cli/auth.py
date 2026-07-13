# SPDX-License-Identifier: Apache-2.0
"""OIDC device authorization with OS-keyring-only bearer-token persistence."""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

SERVICE_NAME = "collective-phase-control-fabric"


class Keyring(Protocol):
    def set_password(self, service_name: str, username: str, password: str) -> None: ...

    def get_password(self, service_name: str, username: str) -> str | None: ...


@dataclass(frozen=True)
class DeviceLoginResult:
    status: str
    code: str
    verification_uri: str | None = None
    user_code: str | None = None
    account: str | None = None


def token_account(environment: Mapping[str, str] | None = None) -> str:
    values = environment if environment is not None else os.environ
    return "|".join(
        (
            values.get("CPCF_API_URL", "https://localhost:8443").rstrip("/"),
            values.get("CPCF_OIDC_CLIENT_ID", "cpcf-cli"),
        )
    )


def system_keyring() -> Keyring | None:
    try:
        import keyring

        backend = keyring.get_keyring()
        if float(getattr(backend, "priority", 0)) <= 0:
            return None
        return keyring
    except (ImportError, RuntimeError):
        return None


def stored_token(
    environment: Mapping[str, str] | None = None,
    *,
    keyring_backend: Keyring | None = None,
) -> str | None:
    values = environment if environment is not None else os.environ
    fallback = values.get("CPCF_TOKEN")
    if fallback:
        return fallback
    backend = keyring_backend or system_keyring()
    if backend is None:
        return None
    try:
        return backend.get_password(SERVICE_NAME, token_account(values))
    except RuntimeError:
        return None


def device_login(
    *,
    environment: Mapping[str, str] | None = None,
    client: httpx.Client | None = None,
    keyring_backend: Keyring | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> DeviceLoginResult:
    """Run RFC 8628 polling and persist only the access token in an OS keyring."""

    values = environment if environment is not None else os.environ
    required = (
        "CPCF_OIDC_DEVICE_AUTHORIZATION_ENDPOINT",
        "CPCF_OIDC_TOKEN_ENDPOINT",
        "CPCF_OIDC_CLIENT_ID",
    )
    if any(not values.get(name) for name in required):
        return DeviceLoginResult("blocked", "oidc_device_configuration_missing")
    device_endpoint = values[required[0]]
    token_endpoint = values[required[1]]
    if not device_endpoint.startswith("https://") or not token_endpoint.startswith("https://"):
        return DeviceLoginResult("error", "oidc_device_endpoint_https_required")
    backend = keyring_backend or system_keyring()
    if backend is None:
        return DeviceLoginResult("blocked", "secure_credential_store_unavailable")
    owned_client = client is None
    session = client or httpx.Client(timeout=30.0, follow_redirects=False)
    try:
        device_response = session.post(
            device_endpoint,
            data={
                "client_id": values[required[2]],
                "scope": values.get("CPCF_OIDC_SCOPE", "openid profile offline_access"),
            },
        )
        device_response.raise_for_status()
        device = device_response.json()
        if not isinstance(device, dict):
            return DeviceLoginResult("error", "oidc_device_response_invalid")
        device_code = device.get("device_code")
        user_code = device.get("user_code")
        verification_uri = device.get("verification_uri")
        expires_in = device.get("expires_in")
        interval = device.get("interval", 5)
        if (
            not isinstance(device_code, str)
            or not isinstance(user_code, str)
            or not isinstance(verification_uri, str)
            or not isinstance(expires_in, int)
            or not 1 <= expires_in <= 1800
            or not isinstance(interval, int)
            or not 1 <= interval <= 60
        ):
            return DeviceLoginResult("error", "oidc_device_response_invalid")
        elapsed = 0
        while elapsed < expires_in:
            response = session.post(
                token_endpoint,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code,
                    "client_id": values[required[2]],
                },
            )
            payload: Any = response.json()
            if response.is_success and isinstance(payload, dict):
                access_token = payload.get("access_token")
                token_type = payload.get("token_type", "Bearer")
                if not isinstance(access_token, str) or token_type.lower() != "bearer":
                    return DeviceLoginResult("error", "oidc_token_response_invalid")
                account = token_account(values)
                try:
                    backend.set_password(SERVICE_NAME, account, access_token)
                except RuntimeError:
                    return DeviceLoginResult("error", "secure_credential_store_write_failed")
                return DeviceLoginResult(
                    "ok",
                    "oidc_device_login_succeeded",
                    verification_uri=verification_uri,
                    user_code=user_code,
                    account=account,
                )
            raw_error = payload.get("error") if isinstance(payload, dict) else None
            error = raw_error if isinstance(raw_error, str) else None
            if error == "slow_down":
                interval = min(interval + 5, 60)
            elif error not in {"authorization_pending"}:
                error_codes = {
                    "access_denied": "oidc_device_access_denied",
                    "expired_token": "oidc_device_code_expired",
                }
                code = error_codes.get(error or "", "oidc_token_response_invalid")
                return DeviceLoginResult(
                    "blocked" if error in {"access_denied", "expired_token"} else "error",
                    code,
                    verification_uri=verification_uri,
                    user_code=user_code,
                )
            sleep(interval)
            elapsed += interval
        return DeviceLoginResult(
            "blocked",
            "oidc_device_code_expired",
            verification_uri=verification_uri,
            user_code=user_code,
        )
    except (httpx.HTTPError, ValueError):
        return DeviceLoginResult("error", "oidc_device_flow_unavailable")
    finally:
        if owned_client:
            session.close()
