# SPDX-License-Identifier: Apache-2.0
"""Tenant-bound immutable S3 CAS adapter."""

from __future__ import annotations

import hashlib
import re
from typing import Any, cast


class S3ObjectStore:
    def __init__(
        self,
        client: Any,
        bucket: str,
        prefix: str = "cpcf",
        maximum_object_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        normalized_prefix = prefix.strip("/")
        if (
            not bucket
            or not normalized_prefix
            or "\\" in normalized_prefix
            or any(segment in {"", ".", ".."} for segment in normalized_prefix.split("/"))
            or maximum_object_bytes < 1
            or maximum_object_bytes > 64 * 1024 * 1024
        ):
            raise ValueError("invalid_object_store_configuration")
        self.client = client
        self.bucket = bucket
        self.prefix = normalized_prefix
        self.maximum_object_bytes = maximum_object_bytes

    @staticmethod
    def _is_not_found(error: Any) -> bool:
        response = getattr(error, "response", {})
        detail = response.get("Error", {}) if isinstance(response, dict) else {}
        metadata = response.get("ResponseMetadata", {}) if isinstance(response, dict) else {}
        code = str(detail.get("Code", "")) if isinstance(detail, dict) else ""
        status = metadata.get("HTTPStatusCode") if isinstance(metadata, dict) else None
        return (
            code
            in {
                "404",
                "NoSuchKey",
                "NotFound",
                "ServerSideEncryptionConfigurationNotFoundError",
            }
            or status == 404
        )

    def _key(self, tenant_id: str, digest: str) -> str:
        if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
            raise ValueError("invalid_content_digest")
        if not tenant_id or any(value in tenant_id for value in ("/", "\\", "..")):
            raise ValueError("invalid_tenant_id")
        return f"{self.prefix}/{tenant_id}/sha256/{digest[7:]}"

    def put(self, tenant_id: str, data: bytes) -> str:
        if len(data) > self.maximum_object_bytes:
            raise ValueError("object_store_input_too_large")
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        return self.put_expected(tenant_id, digest, data)

    def put_expected(self, tenant_id: str, expected_digest: str, data: bytes) -> str:
        """Finalize one digest-scoped upload using conditional immutable creation."""

        if len(data) > self.maximum_object_bytes:
            raise ValueError("object_store_input_too_large")
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        if digest != expected_digest:
            raise ValueError("object_store_expected_digest_mismatch")
        key = self._key(tenant_id, digest)
        try:
            self.client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=data,
                ContentLength=len(data),
                Metadata={"sha256": digest[7:]},
                IfNoneMatch="*",
            )
        except self.client.exceptions.ClientError as error:
            response = getattr(error, "response", {})
            detail = response.get("Error", {}) if isinstance(response, dict) else {}
            code = str(detail.get("Code", "")) if isinstance(detail, dict) else ""
            if code not in {"PreconditionFailed", "ConditionalRequestConflict", "412", "409"}:
                raise
            existing = self.client.head_object(Bucket=self.bucket, Key=key)
            metadata = existing.get("Metadata", {}) if isinstance(existing, dict) else {}
            if (
                int(existing["ContentLength"]) != len(data)
                or not isinstance(metadata, dict)
                or metadata.get("sha256") != digest[7:]
            ):
                raise RuntimeError("immutable_object_key_collision") from error
        return digest

    def quarantine_unreferenced(self, tenant_id: str, digest: str, reason: str) -> None:
        """Mark a CAS upload as non-authoritative after database admission failed."""

        if not reason or len(reason) > 128:
            raise ValueError("invalid_quarantine_reason")
        self.client.put_object_tagging(
            Bucket=self.bucket,
            Key=self._key(tenant_id, digest),
            Tagging={
                "TagSet": [
                    {"Key": "cpcf-authority", "Value": "quarantined"},
                    {"Key": "cpcf-reason", "Value": reason},
                ]
            },
        )

    def validate_bucket_posture(self) -> list[str]:
        """Check versioning and encryption; callers decide whether readiness must fail."""

        reasons: list[str] = []
        versioning = self.client.get_bucket_versioning(Bucket=self.bucket)
        if versioning.get("Status") != "Enabled":
            reasons.append("object_store_versioning_not_enabled")
        try:
            encryption = self.client.get_bucket_encryption(Bucket=self.bucket)
        except self.client.exceptions.ClientError as error:
            if self._is_not_found(error):
                reasons.append("object_store_encryption_not_configured")
            else:
                raise
        else:
            rules = encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if not rules:
                reasons.append("object_store_encryption_not_configured")
        return sorted(set(reasons))

    def get(self, tenant_id: str, digest: str) -> bytes:
        response = self.client.get_object(Bucket=self.bucket, Key=self._key(tenant_id, digest))
        length = int(response.get("ContentLength", self.maximum_object_bytes + 1))
        if length > self.maximum_object_bytes:
            raise RuntimeError("object_store_output_too_large")
        body = response["Body"]
        try:
            data = cast(bytes, body.read(self.maximum_object_bytes + 1))
        finally:
            close = getattr(body, "close", None)
            if callable(close):
                close()
        if len(data) > self.maximum_object_bytes or len(data) != length:
            raise RuntimeError("object_store_output_size_mismatch")
        if "sha256:" + hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError("object_store_digest_mismatch")
        return data

    def exists(self, tenant_id: str, digest: str) -> bool:
        try:
            self.client.head_object(Bucket=self.bucket, Key=self._key(tenant_id, digest))
        except self.client.exceptions.ClientError as error:
            if self._is_not_found(error):
                return False
            raise
        return True
