# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import pytest
from cpcf_api.telemetry import TelemetryConfigurationError, telemetry_settings


def test_telemetry_is_disabled_without_an_explicit_endpoint() -> None:
    assert telemetry_settings({}) is None


def test_telemetry_endpoint_is_credential_free_and_https_by_default() -> None:
    settings = telemetry_settings(
        {
            "CPCF_OTEL_EXPORTER_OTLP_ENDPOINT": "https://collector.example.test/otlp/",
            "CPCF_OTEL_SERVICE_NAME": "cpcf-test",
        }
    )
    assert settings is not None
    assert settings.endpoint == "https://collector.example.test/otlp"
    assert settings.service_name == "cpcf-test"
    with pytest.raises(TelemetryConfigurationError, match="not_acknowledged"):
        telemetry_settings({"CPCF_OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector:4318"})
    with pytest.raises(TelemetryConfigurationError, match="endpoint_invalid"):
        telemetry_settings(
            {"CPCF_OTEL_EXPORTER_OTLP_ENDPOINT": "https://user:secret@collector/otlp"}
        )


def test_insecure_telemetry_requires_exact_development_acknowledgement() -> None:
    settings = telemetry_settings(
        {
            "CPCF_OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector:4318",
            "CPCF_OTEL_ALLOW_INSECURE": "true",
        }
    )
    assert settings is not None and settings.allow_insecure
    with pytest.raises(TelemetryConfigurationError, match="service_name_invalid"):
        telemetry_settings(
            {
                "CPCF_OTEL_EXPORTER_OTLP_ENDPOINT": "https://collector:4318",
                "CPCF_OTEL_SERVICE_NAME": "",
            }
        )
