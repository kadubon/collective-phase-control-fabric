# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import Any

import httpx
import pytest
from cpcf_cli.auth import (
    SERVICE_NAME,
    device_login,
    stored_token,
    token_account,
)


class FakeKeyring:
    def __init__(self, *, fail_write: bool = False, value: str | None = None) -> None:
        self.fail_write = fail_write
        self.value = value
        self.writes: list[tuple[str, str, str]] = []

    def set_password(self, service_name: str, username: str, password: str) -> None:
        if self.fail_write:
            raise RuntimeError("keyring unavailable")
        self.writes.append((service_name, username, password))
        self.value = password

    def get_password(self, service_name: str, username: str) -> str | None:
        assert service_name == SERVICE_NAME
        assert username
        return self.value


class FakeResponse:
    def __init__(self, status_code: int, payload: Any) -> None:
        self.status_code = status_code
        self.payload = payload

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    def raise_for_status(self) -> None:
        if not self.is_success:
            request = httpx.Request("POST", "https://identity.example/device")
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError("request failed", request=request, response=response)

    def json(self) -> Any:
        return self.payload


class FakeClient:
    def __init__(self, responses: list[FakeResponse]) -> None:
        self.responses = list(responses)
        self.requests: list[tuple[str, dict[str, str]]] = []
        self.closed = False

    def post(self, url: str, *, data: dict[str, str]) -> FakeResponse:
        self.requests.append((url, data))
        return self.responses.pop(0)

    def close(self) -> None:
        self.closed = True


def environment() -> dict[str, str]:
    return {
        "CPCF_API_URL": "https://api.example",
        "CPCF_OIDC_DEVICE_AUTHORIZATION_ENDPOINT": "https://identity.example/device",
        "CPCF_OIDC_TOKEN_ENDPOINT": "https://identity.example/token",
        "CPCF_OIDC_CLIENT_ID": "cpcf-cli",
    }


def device_payload(**updates: Any) -> dict[str, Any]:
    return {
        "device_code": "device-code",
        "user_code": "USER-CODE",
        "verification_uri": "https://identity.example/activate",
        "expires_in": 30,
        "interval": 1,
        **updates,
    }


def test_token_lookup_prefers_environment_and_never_requires_plaintext_storage() -> None:
    keyring = FakeKeyring(value="stored-token")
    assert token_account(environment()) == "https://api.example|cpcf-cli"
    assert stored_token(
        {**environment(), "CPCF_TOKEN": "environment-token"}, keyring_backend=keyring
    ) == ("environment-token")
    assert stored_token(environment(), keyring_backend=keyring) == "stored-token"


def test_device_login_requires_configuration_https_and_secure_storage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert device_login(environment={}, keyring_backend=FakeKeyring()).code == (
        "oidc_device_configuration_missing"
    )
    insecure = {**environment(), "CPCF_OIDC_TOKEN_ENDPOINT": "http://identity.example/token"}
    assert device_login(environment=insecure, keyring_backend=FakeKeyring()).code == (
        "oidc_device_endpoint_https_required"
    )
    monkeypatch.setattr("cpcf_cli.auth.system_keyring", lambda: None)
    assert device_login(environment=environment(), keyring_backend=None).code == (
        "secure_credential_store_unavailable"
    )


def test_device_login_polls_pending_and_slow_down_then_writes_keyring() -> None:
    client = FakeClient(
        [
            FakeResponse(200, device_payload()),
            FakeResponse(400, {"error": "authorization_pending"}),
            FakeResponse(400, {"error": "slow_down"}),
            FakeResponse(200, {"access_token": "access-token", "token_type": "Bearer"}),
        ]
    )
    keyring = FakeKeyring()
    sleeps: list[float] = []
    result = device_login(
        environment=environment(),
        client=client,  # type: ignore[arg-type]
        keyring_backend=keyring,
        sleep=sleeps.append,
    )
    assert result.code == "oidc_device_login_succeeded"
    assert result.status == "ok"
    assert result.user_code == "USER-CODE"
    assert result.account == "https://api.example|cpcf-cli"
    assert result.verification_uri == "https://identity.example/activate"
    assert sleeps == [1, 6]
    assert keyring.writes == [(SERVICE_NAME, "https://api.example|cpcf-cli", "access-token")]
    assert all("access-token" not in repr(item) for item in client.requests)
    assert client.requests == [
        (
            "https://identity.example/device",
            {"client_id": "cpcf-cli", "scope": "openid profile offline_access"},
        ),
        *[
            (
                "https://identity.example/token",
                {
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": "device-code",
                    "client_id": "cpcf-cli",
                },
            )
        ]
        * 3,
    ]
    assert not client.closed  # An injected client's lifetime belongs to its caller.


@pytest.mark.parametrize(
    "updates",
    [
        {"device_code": None},
        {"user_code": None},
        {"verification_uri": None},
        {"expires_in": "30"},
        {"expires_in": 0},
        {"expires_in": 1801},
        {"interval": "1"},
        {"interval": 0},
        {"interval": 61},
    ],
)
def test_invalid_device_fields_cannot_poll_or_write_credentials(updates: dict[str, Any]) -> None:
    client = FakeClient([FakeResponse(200, device_payload(**updates))])
    keyring = FakeKeyring()
    result = device_login(
        environment=environment(),
        client=client,  # type: ignore[arg-type]
        keyring_backend=keyring,
    )
    assert (result.status, result.code) == ("error", "oidc_device_response_invalid")
    assert len(client.requests) == 1
    assert keyring.writes == []


@pytest.mark.parametrize("expires_in,interval", [(1, 1), (1800, 60)])
def test_device_field_inclusive_bounds_and_expiry_stop_polling(
    expires_in: int, interval: int
) -> None:
    count = expires_in // interval
    client = FakeClient(
        [FakeResponse(200, device_payload(expires_in=expires_in, interval=interval))]
        + [FakeResponse(400, {"error": "authorization_pending"})] * count
    )
    keyring = FakeKeyring()
    sleeps: list[float] = []
    result = device_login(
        environment=environment(),
        client=client,  # type: ignore[arg-type]
        keyring_backend=keyring,
        sleep=sleeps.append,
    )
    assert (result.status, result.code) == ("blocked", "oidc_device_code_expired")
    assert result.user_code == "USER-CODE"
    assert result.verification_uri == "https://identity.example/activate"
    assert sleeps == [interval] * count
    assert keyring.writes == []


@pytest.mark.parametrize(
    "payload", [{"access_token": 1}, {"access_token": "x", "token_type": "MAC"}]
)
def test_success_http_status_does_not_admit_invalid_token(payload: dict[str, Any]) -> None:
    keyring = FakeKeyring()
    result = device_login(
        environment=environment(),
        client=FakeClient([FakeResponse(200, device_payload()), FakeResponse(200, payload)]),  # type: ignore[arg-type]
        keyring_backend=keyring,
    )
    assert (result.status, result.code) == ("error", "oidc_token_response_invalid")
    assert keyring.writes == []


@pytest.mark.parametrize(
    ("token_payload", "expected"),
    [
        ({"error": "access_denied"}, "oidc_device_access_denied"),
        ({"error": "expired_token"}, "oidc_device_code_expired"),
        ({"error": "server_error"}, "oidc_token_response_invalid"),
        ({"access_token": 1}, "oidc_token_response_invalid"),
        ({"access_token": "token", "token_type": "MAC"}, "oidc_token_response_invalid"),
    ],
)
def test_device_login_fails_closed_for_terminal_and_malformed_responses(
    token_payload: dict[str, Any], expected: str
) -> None:
    result = device_login(
        environment=environment(),
        client=FakeClient([FakeResponse(200, device_payload()), FakeResponse(400, token_payload)]),  # type: ignore[arg-type]
        keyring_backend=FakeKeyring(),
        sleep=lambda _: None,
    )
    assert result.code == expected


def test_device_login_rejects_malformed_device_response_and_keyring_write_failure() -> None:
    malformed = device_login(
        environment=environment(),
        client=FakeClient([FakeResponse(200, device_payload(expires_in=0))]),  # type: ignore[arg-type]
        keyring_backend=FakeKeyring(),
    )
    assert malformed.code == "oidc_device_response_invalid"
    failed_write = device_login(
        environment=environment(),
        client=FakeClient(  # type: ignore[arg-type]
            [
                FakeResponse(200, device_payload()),
                FakeResponse(200, {"access_token": "token", "token_type": "Bearer"}),
            ]
        ),
        keyring_backend=FakeKeyring(fail_write=True),
    )
    assert failed_write.code == "secure_credential_store_write_failed"


def test_device_login_maps_transport_failure_without_leaking_values() -> None:
    result = device_login(
        environment=environment(),
        client=FakeClient([FakeResponse(500, {})]),  # type: ignore[arg-type]
        keyring_backend=FakeKeyring(),
    )
    assert result.code == "oidc_device_flow_unavailable"
