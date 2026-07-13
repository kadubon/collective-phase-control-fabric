# SPDX-License-Identifier: Apache-2.0
"""Tenant-bound immutable S3 CAS adapter."""

from __future__ import annotations

import hashlib
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
        return code in {"404", "NoSuchKey", "NotFound"} or status == 404

    def _key(self, tenant_id: str, digest: str) -> str:
        if not digest.startswith("sha256:") or len(digest) != 71:
            raise ValueError("invalid_content_digest")
        if not tenant_id or any(value in tenant_id for value in ("/", "\\", "..")):
            raise ValueError("invalid_tenant_id")
        return f"{self.prefix}/{tenant_id}/sha256/{digest[7:]}"

    def put(self, tenant_id: str, data: bytes) -> str:
        if len(data) > self.maximum_object_bytes:
            raise ValueError("object_store_input_too_large")
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        key = self._key(tenant_id, digest)
        try:
            existing = self.client.head_object(Bucket=self.bucket, Key=key)
        except self.client.exceptions.ClientError as error:
            if not self._is_not_found(error):
                raise
            self.client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=data,
                ContentLength=len(data),
                Metadata={"sha256": digest[7:]},
            )
        else:
            metadata = existing.get("Metadata", {})
            if (
                int(existing["ContentLength"]) != len(data)
                or not isinstance(metadata, dict)
                or metadata.get("sha256") != digest[7:]
            ):
                raise RuntimeError("immutable_object_key_collision")
        return digest

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
