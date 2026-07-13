# SPDX-License-Identifier: Apache-2.0
"""Static KMS/HSM signer adapters; production private keys never enter CPCF memory."""

from __future__ import annotations

import base64
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from collective_phase_control_fabric.v6.trust import P256_ORDER


class KmsSigner(Protocol):
    key_uri: str
    algorithm: str

    def sign(self, message: bytes) -> bytes: ...


def normalize_p256_der(signature: bytes) -> bytes:
    r, s = decode_dss_signature(signature)
    return normalize_p256_raw(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def normalize_p256_raw(signature: bytes) -> bytes:
    if len(signature) != 64:
        raise ValueError("kms_ecdsa_signature_length_invalid")
    r = int.from_bytes(signature[:32], "big")
    raw_s = int.from_bytes(signature[32:], "big")
    if r <= 0 or r >= P256_ORDER or raw_s <= 0 or raw_s >= P256_ORDER:
        raise ValueError("kms_ecdsa_signature_out_of_range")
    s = min(raw_s, P256_ORDER - raw_s)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


class AwsKmsSigner:
    algorithm = "ecdsa-p256-sha256"

    def __init__(self, client: Any, key_uri: str) -> None:
        self.client = client
        self.key_uri = key_uri

    def sign(self, message: bytes) -> bytes:
        result = self.client.sign(
            KeyId=self.key_uri,
            Message=message,
            MessageType="RAW",
            SigningAlgorithm="ECDSA_SHA_256",
        )
        return normalize_p256_der(bytes(result["Signature"]))


class GoogleKmsSigner:
    algorithm = "ecdsa-p256-sha256"

    def __init__(self, client: Any, key_uri: str) -> None:
        self.client = client
        self.key_uri = key_uri

    def sign(self, message: bytes) -> bytes:
        import hashlib

        response = self.client.asymmetric_sign(
            request={"name": self.key_uri, "digest": {"sha256": hashlib.sha256(message).digest()}}
        )
        return normalize_p256_der(bytes(response.signature))


class AzureKeyVaultSigner:
    algorithm = "ecdsa-p256-sha256"

    def __init__(self, cryptography_client: Any, key_uri: str) -> None:
        self.client = cryptography_client
        self.key_uri = key_uri

    def sign(self, message: bytes) -> bytes:
        import hashlib

        response = self.client.sign("ES256", hashlib.sha256(message).digest())
        signature = bytes(response.signature)
        if len(signature) == 64:
            return normalize_p256_raw(signature)
        return normalize_p256_der(signature)


class Pkcs11Signer:
    algorithm = "ecdsa-p256-sha256"

    def __init__(self, private_key: Any, key_uri: str) -> None:
        self.private_key = private_key
        self.key_uri = key_uri

    def sign(self, message: bytes) -> bytes:
        signature = bytes(self.private_key.sign(message, mechanism="ECDSA_SHA256"))
        if len(signature) != 64:
            return normalize_p256_der(signature)
        return normalize_p256_raw(signature)


def encode_signature(signature: bytes) -> str:
    return base64.b64encode(signature).decode("ascii")


SIGNER_DRIVERS = {
    "aws-kms": AwsKmsSigner,
    "gcp-kms": GoogleKmsSigner,
    "azure-key-vault": AzureKeyVaultSigner,
    "pkcs11": Pkcs11Signer,
}
