# SPDX-License-Identifier: Apache-2.0
"""Opt-in OpenTelemetry wiring that never records evidence payloads."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response


class TelemetryConfigurationError(RuntimeError):
    """Stable fail-closed telemetry configuration error."""


@dataclass(frozen=True)
class TelemetrySettings:
    endpoint: str
    service_name: str
    allow_insecure: bool


def telemetry_settings(
    environ: Mapping[str, str] | None = None,
) -> TelemetrySettings | None:
    values = os.environ if environ is None else environ
    raw_endpoint = values.get("CPCF_OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
    if not raw_endpoint:
        return None
    endpoint = raw_endpoint.rstrip("/")
    parsed = urlsplit(endpoint)
    allow_insecure = values.get("CPCF_OTEL_ALLOW_INSECURE") == "true"
    if (
        parsed.scheme not in {"https", "http"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise TelemetryConfigurationError("otel_endpoint_invalid")
    if parsed.scheme != "https" and not allow_insecure:
        raise TelemetryConfigurationError("otel_insecure_endpoint_not_acknowledged")
    service_name = values.get("CPCF_OTEL_SERVICE_NAME", "cpcf-api").strip()
    if not service_name or len(service_name) > 128:
        raise TelemetryConfigurationError("otel_service_name_invalid")
    return TelemetrySettings(endpoint, service_name, allow_insecure)


def configure_telemetry(app: FastAPI, settings: TelemetrySettings | None) -> bool:
    """Install OTLP tracing and metrics without request paths, headers, or bodies."""

    if settings is None:
        return False
    from opentelemetry import metrics, trace
    from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    resource = Resource.create({"service.name": settings.service_name})
    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=settings.endpoint + "/v1/traces"))
    )
    metric_reader = PeriodicExportingMetricReader(
        OTLPMetricExporter(endpoint=settings.endpoint + "/v1/metrics")
    )
    meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
    trace.set_tracer_provider(tracer_provider)
    metrics.set_meter_provider(meter_provider)
    tracer = tracer_provider.get_tracer("cpcf-api")
    requests = meter_provider.get_meter("cpcf-api").create_counter("cpcf.http.server.requests")

    @app.middleware("http")
    async def observe(request: Request, call_next: RequestResponseEndpoint) -> Response:
        method = request.method
        with tracer.start_as_current_span(
            "http.request", attributes={"http.request.method": method}
        ) as span:
            response = await call_next(request)
            status_code = response.status_code
            span.set_attribute("http.response.status_code", status_code)
            requests.add(
                1, {"http.request.method": method, "http.response.status_code": status_code}
            )
            return response

    app.state.telemetry_enabled = True
    return True
