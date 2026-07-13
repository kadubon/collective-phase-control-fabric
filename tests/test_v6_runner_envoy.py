# SPDX-License-Identifier: Apache-2.0
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_runner_envoy_contract_is_mtls_sanitized_and_loopback_only() -> None:
    configuration = (ROOT / "deploy" / "envoy" / "runner-gateway.yaml").read_text(encoding="utf-8")
    assert "require_client_certificate: true" in configuration
    assert "tls_minimum_protocol_version: TLSv1_3" in configuration
    assert "forward_client_cert_details: SANITIZE_SET" in configuration
    assert "trusted_ca: {filename: /etc/cpcf/runner-tls/ca.crt}" in configuration
    assert "socket_address: {address: 127.0.0.1, port_value: 8081}" in configuration
    assert "x-cpcf-runner-principal" in configuration
    assert "request_headers_to_add" not in configuration
