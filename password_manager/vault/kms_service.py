"""Abstractions for interacting with the Key Management Service (KMS)."""

from __future__ import annotations

import base64
import json
import os
import threading
from dataclasses import dataclass
from typing import Dict, Optional

# boto3 is only required when talking to AWS KMS. Import lazily so development
# environments without boto3 can still run using the software fallback.
try:  # pragma: no cover - import guard
    import boto3  # type: ignore
    from botocore.exceptions import BotoCoreError, ClientError
except ModuleNotFoundError:  # pragma: no cover - gracefully handle missing dependency
    boto3 = None

    class BotoCoreError(Exception):
        """Fallback error type when botocore is unavailable."""

    class ClientError(Exception):
        """Fallback error type when botocore is unavailable."""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from core.logging_utils import get_security_logger
from vault.exceptions import CryptoError

logger = get_security_logger()


@dataclass(frozen=True)
class KMSEncryptResponse:
    """Structured response for encryption operations."""

    ciphertext_blob: bytes
    key_id: str
    encryption_algorithm: str


class BaseKMSService:
    """Interface for KMS-like services."""

    def encrypt(self, *, plaintext: bytes, encryption_context: Dict[str, str]) -> KMSEncryptResponse:  # pragma: no cover - abstract
        raise NotImplementedError

    def decrypt(
        self,
        *,
        ciphertext_blob: bytes,
        encryption_context: Dict[str, str],
        kms_key_id: str,
        encryption_algorithm: str,
    ) -> bytes:  # pragma: no cover - abstract
        raise NotImplementedError


class AWSKMSService(BaseKMSService):
    """Production-ready KMS adapter backed by AWS KMS."""

    def __init__(self, alias: str, *, region: Optional[str], endpoint_url: Optional[str]):
        self.alias = alias
        session_kwargs = {}
        if region:
            session_kwargs["region_name"] = region
        if endpoint_url:
            session_kwargs["endpoint_url"] = endpoint_url
        self._client = boto3.client("kms", **session_kwargs)

    def encrypt(self, *, plaintext: bytes, encryption_context: Dict[str, str]) -> KMSEncryptResponse:
        try:
            response = self._client.encrypt(
                KeyId=self.alias,
                Plaintext=plaintext,
                EncryptionContext=encryption_context,
            )
        except (ClientError, BotoCoreError) as exc:
            logger.error("AWS KMS encrypt call failed", extra={"context": {"error": str(exc)}})
            raise CryptoError("AWS KMS encrypt call failed") from exc

        return KMSEncryptResponse(
            ciphertext_blob=response["CiphertextBlob"],
            key_id=response["KeyId"],
            encryption_algorithm=response.get("EncryptionAlgorithm", "SYMMETRIC_DEFAULT"),
        )

    def decrypt(
        self,
        *,
        ciphertext_blob: bytes,
        encryption_context: Dict[str, str],
        kms_key_id: str,
        encryption_algorithm: str,
    ) -> bytes:
        decrypt_kwargs = {
            "CiphertextBlob": ciphertext_blob,
            "EncryptionContext": encryption_context,
            "KeyId": kms_key_id,
        }
        if encryption_algorithm and encryption_algorithm != "SYMMETRIC_DEFAULT":
            decrypt_kwargs["EncryptionAlgorithm"] = encryption_algorithm

        try:
            response = self._client.decrypt(**decrypt_kwargs)
        except (ClientError, BotoCoreError) as exc:
            logger.error("AWS KMS decrypt call failed", extra={"context": {"error": str(exc)}})
            raise CryptoError("AWS KMS decrypt call failed") from exc

        return response["Plaintext"]


class SoftwareKMSService(BaseKMSService):
    """Deterministic AES-GCM based fallback for local development and tests."""

    def __init__(self, *, key_material: bytes):
        if len(key_material) != 32:
            raise ImproperlyConfigured("Software KMS requires a 32-byte key")
        self._key_material = key_material
        self._aesgcm = AESGCM(key_material)
        self._key_id = "local/dev"

    @staticmethod
    def _serialize_context(encryption_context: Dict[str, str]) -> bytes:
        return json.dumps(encryption_context, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def encrypt(self, *, plaintext: bytes, encryption_context: Dict[str, str]) -> KMSEncryptResponse:
        aad = self._serialize_context(encryption_context)
        nonce = os.urandom(12)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, aad)
        return KMSEncryptResponse(
            ciphertext_blob=nonce + ciphertext,
            key_id=self._key_id,
            encryption_algorithm="AES_GCM",
        )

    def decrypt(
        self,
        *,
        ciphertext_blob: bytes,
        encryption_context: Dict[str, str],
        kms_key_id: str,
        encryption_algorithm: str,
    ) -> bytes:
        if kms_key_id != self._key_id:
            raise CryptoError("Software KMS received unexpected key identifier")

        aad = self._serialize_context(encryption_context)
        nonce, ciphertext = ciphertext_blob[:12], ciphertext_blob[12:]
        return self._aesgcm.decrypt(nonce, ciphertext, aad)


_service_instance: Optional[BaseKMSService] = None
_service_lock = threading.Lock()


def _build_service() -> BaseKMSService:
    alias = getattr(settings, "VAULT_KMS_KEY_ALIAS", None)
    if not alias:
        raise ImproperlyConfigured("VAULT_KMS_KEY_ALIAS must be configured")

    alias_is_local = alias.startswith("local/")
    endpoint = getattr(settings, "VAULT_KMS_ENDPOINT", None)
    region = getattr(settings, "VAULT_KMS_REGION", None)
    fallback_enabled = getattr(settings, "VAULT_KMS_ALLOW_SOFTWARE_FALLBACK", alias_is_local)

    if alias_is_local:
        logger.warning("Using software KMS fallback for alias %s", alias)

    if alias_is_local or fallback_enabled:
        key_material_b64 = getattr(settings, "VAULT_KMS_DEV_KEY", None)
        if key_material_b64:
            key_material = base64.b64decode(key_material_b64)
        else:
            import hashlib

            secret = getattr(settings, "SECRET_KEY", "local-secret")
            key_material = hashlib.sha256(secret.encode("utf-8")).digest()
            logger.warning(
                "No VAULT_KMS_DEV_KEY provided; deriving development KMS key from SECRET_KEY. "
                "Do NOT use this mode in production."
            )
        return SoftwareKMSService(key_material=key_material)

    if boto3 is None:
        raise ImproperlyConfigured(
            "boto3 is required for AWS KMS operations but is not installed. "
            "Install boto3 or enable the software fallback via VAULT_KMS_ALLOW_SOFTWARE_FALLBACK."
        )

    return AWSKMSService(alias, region=region, endpoint_url=endpoint)


def get_kms_service() -> BaseKMSService:
    """Return a singleton KMS service instance."""

    global _service_instance
    if _service_instance is not None:
        return _service_instance

    with _service_lock:
        if _service_instance is None:
            _service_instance = _build_service()
    return _service_instance
