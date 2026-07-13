# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest
from cpcf_api.auth import OidcAuthenticator, PrincipalContext, authorize
from cpcf_api.main import main as api_main
from cpcf_cli.main import _headers, _legacy_command_is_read_only, _request, build_parser
from cpcf_cli.main import main as cli_entry
from cpcf_runner_protocol import RunnerConformance, __version__, validate_receipt
from cpcf_worker.main import run_once

ROOT = Path(__file__).resolve().parents[1]


def test_cli_parser_and_environment_only_authentication(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    parser = build_parser()
    assert parser.parse_args(["workspace", "status", "workspace-a"]).workspace == "workspace-a"
    monkeypatch.delenv("CPCF_TOKEN", raising=False)
    assert cli_entry(["auth", "login", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["code"] == "bearer_token_required"
    with pytest.raises(RuntimeError, match="CPCF_TOKEN"):
        _headers()
    assert _headers(authenticated=False) == {}
    monkeypatch.setenv("CPCF_TOKEN", "ephemeral-token")
    monkeypatch.setenv("CPCF_IDEMPOTENCY_KEY", "i" * 32)
    headers = _headers(mutation=True, generation="sha256:" + "a" * 64)
    assert headers["Authorization"] == "Bearer ephemeral-token"
    assert headers["Idempotency-Key"] == "i" * 32
    assert headers["If-Match"] == "sha256:" + "a" * 64


def test_legacy_bridge_is_read_only(capsys: pytest.CaptureFixture[str]) -> None:
    assert _legacy_command_is_read_only(["doctor", "--workspace", "legacy", "--json"])
    assert not _legacy_command_is_read_only(
        ["control", "run", "--workspace", "legacy", "action", "--apply", "--json"]
    )
    assert (
        cli_entry(
            [
                "legacy",
                "inspect",
                "control",
                "run",
                "--workspace",
                "legacy",
                "action",
                "--apply",
                "--json",
            ]
        )
        == 1
    )
    assert json.loads(capsys.readouterr().out)["code"] == "legacy_mutation_blocked"


def test_uv_lock_is_present_and_not_ignored() -> None:
    assert (ROOT / "uv.lock").is_file()
    ignored = {
        line.strip() for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    }
    assert "/uv.lock" not in ignored


def test_cli_request_reports_control_plane_failures_without_token_leakage(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("CPCF_TOKEN", "secret-not-for-output")

    class FailedClient:
        def __init__(self, **_: object) -> None:
            pass

        def __enter__(self) -> FailedClient:
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def request(self, *_: object, **__: object) -> httpx.Response:
            raise httpx.ConnectError("connection unavailable")

    monkeypatch.setattr(httpx, "Client", FailedClient)
    assert _request("GET", "/health/ready") == 1
    output = capsys.readouterr().out
    assert "control_plane_unavailable" in output
    assert "secret-not-for-output" not in output


def test_authz_runner_exports_and_process_entrypoint_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal = PrincipalContext(
        subject="user",
        tenant_id="tenant-a",
        roles=frozenset({"auditor"}),
    )
    authorize(principal, "workspace:read", "tenant-a")
    with pytest.raises(PermissionError, match="cross_tenant"):
        authorize(principal, "workspace:read", "tenant-b")
    with pytest.raises(PermissionError, match="denied_by_default"):
        authorize(principal, "workspace:create", "tenant-a")
    with pytest.raises(ValueError, match="HTTPS"):
        OidcAuthenticator("http://issuer", "audience", "http://issuer/jwks")
    with pytest.raises(ValueError, match="maximum token lifetime"):
        OidcAuthenticator(
            "https://issuer",
            "audience",
            "https://issuer/jwks",
            maximum_token_lifetime_seconds=1,
        )

    assert __version__ == "0.6.0"
    assert RunnerConformance(accepted=True, code="ok").accepted
    assert callable(validate_receipt)

    monkeypatch.delenv("CPCF_DATABASE_URL", raising=False)
    monkeypatch.delenv("CPCF_WORKER_TENANT", raising=False)
    with pytest.raises(RuntimeError, match="CPCF_DATABASE_URL"):
        asyncio.run(run_once())
    assert api_main() == 2
