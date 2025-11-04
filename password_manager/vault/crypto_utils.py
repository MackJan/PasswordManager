"""Cryptographic utilities for the password manager vault."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings

from core.logging_utils import get_security_logger
from vault.exceptions import CryptoError
from vault.kms_service import get_kms_service

logger = get_security_logger()


@dataclass(frozen=True)
class UMKWrapResult:
    """Result payload when wrapping a user master key."""

    wrapped_umk_b64: str
    encryption_context: Dict[str, str]
    kms_key_id: str
    kms_encryption_algorithm: str
    amk_version: int


def generate_key() -> bytes:
    """Generate a cryptographically secure 32-byte key."""

    return os.urandom(32)


def generate_nonce() -> bytes:
    """Generate a cryptographically secure 12-byte nonce for AES-GCM."""

    return os.urandom(12)


def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
    """Encrypt data using AES-256-GCM AEAD."""

    if len(key) != 32:
        raise CryptoError("Key must be 32 bytes for AES-256")

    nonce = generate_nonce()
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    """Decrypt data using AES-256-GCM AEAD."""

    if len(key) != 32:
        raise CryptoError("Key must be 32 bytes for AES-256")

    try:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:  # pragma: no cover - difficult to simulate exact error chains
        context_data = {
            "key_length": len(key),
            "nonce_length": len(nonce),
            "ciphertext_length": len(ciphertext),
            "aad": aad.decode("utf-8", errors="replace"),
        }
        logger.error("AEAD authentication failed", extra_data=context_data)
        raise CryptoError("Authentication failed - data may be corrupted or tampered with") from exc
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.error("Unexpected AEAD error", extra_data={"error": str(exc)})
        raise CryptoError(f"Decryption failed: {exc}") from exc


def create_aad(
    user_id: int,
    item_id: str | None = None,
    *,
    algo_version: int = 1,
    amk_version: int | None = None,
) -> bytes:
    """Create Additional Authenticated Data (AAD) for AEAD encryption."""

    aad_dict: Dict[str, Any] = {
        "user_id": user_id,
        "algo_version": algo_version,
    }

    if item_id:
        aad_dict["item_id"] = str(item_id)

    if amk_version is not None:
        aad_dict["amk_version"] = amk_version

    aad_json = json.dumps(aad_dict, sort_keys=True, separators=(",", ":"))
    return aad_json.encode("utf-8")


def wrap_umk(umk: bytes, user_id: int, *, amk_version: int | None = None) -> UMKWrapResult:
    """Wrap a user master key with the application master key stored in KMS."""

    if len(umk) != 32:
        raise CryptoError("UMK must be 32 bytes")

    if amk_version is None:
        amk_version = int(getattr(settings, "VAULT_AMK_VERSION", 1))

    kms_service = get_kms_service()
    encryption_context = {
        "purpose": "umk-wrap",
        "user_id": str(user_id),
        "amk_version": str(amk_version),
    }

    try:
        response = kms_service.encrypt(plaintext=umk, encryption_context=encryption_context)
    except Exception as exc:  # pragma: no cover - dependency failure
        logger.error("KMS encrypt failed", extra_data={"error": str(exc)})
        raise CryptoError("Failed to wrap UMK via KMS") from exc

    ciphertext_blob = response.ciphertext_blob
    wrapped_umk_b64 = base64.b64encode(ciphertext_blob).decode("ascii")

    return UMKWrapResult(
        wrapped_umk_b64=wrapped_umk_b64,
        encryption_context=encryption_context,
        kms_key_id=response.key_id,
        kms_encryption_algorithm=response.encryption_algorithm,
        amk_version=amk_version,
    )


def unwrap_umk(
    wrapped_umk_b64: str,
    *,
    encryption_context: Dict[str, str],
    kms_key_id: str,
    kms_encryption_algorithm: str,
) -> bytes:
    """Unwrap a user master key using the application master key in KMS."""

    ciphertext = base64.b64decode(wrapped_umk_b64)
    kms_service = get_kms_service()

    try:
        plaintext = kms_service.decrypt(
            ciphertext_blob=ciphertext,
            encryption_context=encryption_context,
            kms_key_id=kms_key_id,
            encryption_algorithm=kms_encryption_algorithm,
        )
    except Exception as exc:  # pragma: no cover - dependency failure
        logger.error("KMS decrypt failed", extra_data={"error": str(exc)})
        raise CryptoError("Failed to unwrap UMK via KMS", recoverable=False) from exc

    if len(plaintext) != 32:
        raise CryptoError("Invalid UMK length after KMS unwrap")

    return plaintext


def wrap_dek(dek: bytes, umk: bytes, item_id: str, *, algo_version: int = 1) -> Tuple[str, str]:
    """Wrap a data encryption key with the user's master key."""

    if len(dek) != 32 or len(umk) != 32:
        raise CryptoError("DEK and UMK must both be 32 bytes")

    aad = create_aad(0, item_id=item_id, algo_version=algo_version)
    nonce, ciphertext = aead_encrypt(umk, dek, aad)
    return (
        base64.b64encode(ciphertext).decode("ascii"),
        base64.b64encode(nonce).decode("ascii"),
    )


def unwrap_dek(
    wrapped_dek_b64: str,
    nonce_b64: str,
    umk: bytes,
    item_id: str,
    *,
    algo_version: int = 1,
) -> bytes:
    """Unwrap a data encryption key using the user's master key."""

    wrapped_dek = base64.b64decode(wrapped_dek_b64)
    nonce = base64.b64decode(nonce_b64)
    aad = create_aad(0, item_id=item_id, algo_version=algo_version)
    dek = aead_decrypt(umk, nonce, wrapped_dek, aad)
    if len(dek) != 32:
        raise CryptoError("Invalid DEK length after unwrap")
    return dek


def encrypt_item_data(
    item_data: Dict[str, Any],
    dek: bytes,
    user_id: int,
    item_id: str,
    *,
    algo_version: int = 1,
) -> Tuple[str, str]:
    """Encrypt item data using the supplied data encryption key."""

    if len(dek) != 32:
        raise CryptoError("DEK must be 32 bytes")

    item_json = json.dumps(item_data, sort_keys=True, separators=(",", ":"))
    plaintext = item_json.encode("utf-8")
    aad = create_aad(user_id, item_id=item_id, algo_version=algo_version)
    nonce, ciphertext = aead_encrypt(dek, plaintext, aad)
    return (
        base64.b64encode(ciphertext).decode("ascii"),
        base64.b64encode(nonce).decode("ascii"),
    )


def decrypt_item_data(
    ciphertext_b64: str,
    nonce_b64: str,
    dek: bytes,
    user_id: int,
    item_id: str,
    *,
    algo_version: int = 1,
) -> Dict[str, Any]:
    """Decrypt item data with the supplied data encryption key."""

    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)
    aad = create_aad(user_id, item_id=item_id, algo_version=algo_version)
    plaintext = aead_decrypt(dek, nonce, ciphertext, aad)
    item_json = plaintext.decode("utf-8")
    return json.loads(item_json)


def secure_zero(data: bytes | bytearray | memoryview | None) -> None:
    """Best-effort secure zeroing of sensitive data in memory."""

    if not data:
        return

    try:
        if isinstance(data, bytearray):
            for idx in range(len(data)):
                data[idx] = 0
            return

        if isinstance(data, memoryview):
            data[:] = b"\x00" * len(data)
            return

        if isinstance(data, bytes):
            mutable = bytearray(data)
            for idx in range(len(mutable)):
                mutable[idx] = 0
    except Exception as exc:  # pragma: no cover - best effort logging
        logger.warning("Secure zero attempt failed", extra_data={"error": str(exc)})
