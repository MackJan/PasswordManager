"""
Cryptographic utilities for the password manager vault.
Implements AES-256-GCM AEAD encryption workflow as specified.
"""

import os
import json
import base64
from typing import Dict, Any, Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from django.conf import settings


class CryptoError(Exception):
    """Base exception for cryptographic operations"""
    pass


class AMKManager:
    """Application Master Key manager"""

    def __init__(self):
        self._amk_cache = {}
        self._load_amks()

    def _load_amks(self):
        """Load AMKs from environment variables or secure storage"""
        # In production, load from secure file storage
        # For now, use environment variables with fallback
        amk_v1 = os.environ.get('AMK_V1')
        if amk_v1:
            self._amk_cache[1] = base64.b64decode(amk_v1)
        else:
            # Generate a default AMK for development (DO NOT USE IN PRODUCTION)
            self._amk_cache[1] = os.urandom(32)

    def get_amk(self, version: int = 1) -> bytes:
        """Get AMK by version"""
        if version not in self._amk_cache:
            raise CryptoError(f"AMK version {version} not found")
        return self._amk_cache[version]

    def get_latest_version(self) -> int:
        """Get the latest AMK version"""
        return max(self._amk_cache.keys()) if self._amk_cache else 1


# Global AMK manager instance
amk_manager = AMKManager()


def generate_key() -> bytes:
    """Generate a cryptographically secure 32-byte key"""
    return os.urandom(32)


def generate_nonce() -> bytes:
    """Generate a cryptographically secure 12-byte nonce for AES-GCM"""
    return os.urandom(12)


def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b'') -> Tuple[bytes, bytes]:
    """
    Encrypt data using AES-256-GCM AEAD

    Args:
        key: 32-byte encryption key
        plaintext: Data to encrypt
        aad: Additional authenticated data

    Returns:
        Tuple of (nonce, ciphertext_with_tag)
    """
    if len(key) != 32:
        raise CryptoError("Key must be 32 bytes for AES-256")

    nonce = generate_nonce()
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    return nonce, ciphertext


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b'') -> bytes:
    """
    Decrypt data using AES-256-GCM AEAD

    Args:
        key: 32-byte encryption key
        nonce: 12-byte nonce
        ciphertext: Encrypted data with authentication tag
        aad: Additional authenticated data

    Returns:
        Decrypted plaintext

    Raises:
        CryptoError: If decryption or authentication fails
    """
    if len(key) != 32:
        raise CryptoError("Key must be 32 bytes for AES-256")

    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        return plaintext
    except InvalidTag:
        raise CryptoError("Authentication failed - data may be corrupted or tampered with")


def create_aad(user_id: int, item_id: str = None, algo_version: int = 1, amk_version: int = None) -> bytes:
    """
    Create Additional Authenticated Data (AAD) for AEAD encryption

    Args:
        user_id: User ID
        item_id: Item ID (optional, for item-level encryption)
        algo_version: Algorithm version
        amk_version: AMK version (optional, for UMK encryption)

    Returns:
        AAD bytes
    """
    aad_dict = {
        'user_id': user_id,
        'algo_version': algo_version
    }

    if item_id:
        aad_dict['item_id'] = str(item_id)

    if amk_version is not None:
        aad_dict['amk_version'] = amk_version

    # Create deterministic AAD by sorting keys
    aad_json = json.dumps(aad_dict, sort_keys=True, separators=(',', ':'))
    return aad_json.encode('utf-8')


def wrap_umk(umk: bytes, user_id: int, amk_version: int = None) -> Tuple[str, str, int]:
    """
    Wrap User Master Key with Application Master Key

    Args:
        umk: 32-byte User Master Key
        user_id: User ID for AAD
        amk_version: AMK version to use (defaults to latest)

    Returns:
        Tuple of (wrapped_umk_b64, nonce_b64, amk_version_used)
    """
    if amk_version is None:
        amk_version = amk_manager.get_latest_version()

    amk = amk_manager.get_amk(amk_version)
    aad = create_aad(user_id, algo_version=1, amk_version=amk_version)

    nonce, ciphertext = aead_encrypt(amk, umk, aad)

    return (
        base64.b64encode(ciphertext).decode('ascii'),
        base64.b64encode(nonce).decode('ascii'),
        amk_version
    )


def unwrap_umk(wrapped_umk_b64: str, nonce_b64: str, user_id: int, amk_version: int, algo_version: int = 1) -> bytes:
    """
    Unwrap User Master Key using Application Master Key

    Args:
        wrapped_umk_b64: Base64-encoded wrapped UMK
        nonce_b64: Base64-encoded nonce
        user_id: User ID for AAD
        amk_version: AMK version used for encryption
        algo_version: Algorithm version

    Returns:
        32-byte User Master Key
    """
    amk = amk_manager.get_amk(amk_version)
    wrapped_umk = base64.b64decode(wrapped_umk_b64)
    nonce = base64.b64decode(nonce_b64)
    aad = create_aad(user_id, algo_version=algo_version, amk_version=amk_version)

    umk = aead_decrypt(amk, nonce, wrapped_umk, aad)

    if len(umk) != 32:
        raise CryptoError("Invalid UMK length after decryption")

    return umk


def wrap_dek(dek: bytes, umk: bytes, item_id: str, algo_version: int = 1) -> Tuple[str, str]:
    """
    Wrap Data Encryption Key with User Master Key

    Args:
        dek: 32-byte Data Encryption Key
        umk: 32-byte User Master Key
        item_id: Item ID for AAD
        algo_version: Algorithm version

    Returns:
        Tuple of (wrapped_dek_b64, nonce_b64)
    """
    aad = create_aad(0, item_id=item_id, algo_version=algo_version)  # user_id not needed for DEK wrapping
    nonce, ciphertext = aead_encrypt(umk, dek, aad)

    return (
        base64.b64encode(ciphertext).decode('ascii'),
        base64.b64encode(nonce).decode('ascii')
    )


def unwrap_dek(wrapped_dek_b64: str, nonce_b64: str, umk: bytes, item_id: str, algo_version: int = 1) -> bytes:
    """
    Unwrap Data Encryption Key using User Master Key

    Args:
        wrapped_dek_b64: Base64-encoded wrapped DEK
        nonce_b64: Base64-encoded nonce
        umk: 32-byte User Master Key
        item_id: Item ID for AAD
        algo_version: Algorithm version

    Returns:
        32-byte Data Encryption Key
    """
    wrapped_dek = base64.b64decode(wrapped_dek_b64)
    nonce = base64.b64decode(nonce_b64)
    aad = create_aad(0, item_id=item_id, algo_version=algo_version)  # user_id not needed for DEK wrapping

    dek = aead_decrypt(umk, nonce, wrapped_dek, aad)

    if len(dek) != 32:
        raise CryptoError("Invalid DEK length after decryption")

    return dek


def encrypt_item_data(item_data: Dict[str, Any], dek: bytes, user_id: int, item_id: str, algo_version: int = 1) -> Tuple[str, str]:
    """
    Encrypt item data using Data Encryption Key

    Args:
        item_data: Dictionary containing item fields (name, username, password, etc.)
        dek: 32-byte Data Encryption Key
        user_id: User ID for AAD
        item_id: Item ID for AAD
        algo_version: Algorithm version

    Returns:
        Tuple of (ciphertext_b64, nonce_b64)
    """
    item_json = json.dumps(item_data, sort_keys=True, separators=(',', ':'))
    plaintext = item_json.encode('utf-8')
    aad = create_aad(user_id, item_id=item_id, algo_version=algo_version)

    nonce, ciphertext = aead_encrypt(dek, plaintext, aad)

    return (
        base64.b64encode(ciphertext).decode('ascii'),
        base64.b64encode(nonce).decode('ascii')
    )


def decrypt_item_data(ciphertext_b64: str, nonce_b64: str, dek: bytes, user_id: int, item_id: str, algo_version: int = 1) -> Dict[str, Any]:
    """
    Decrypt item data using Data Encryption Key

    Args:
        ciphertext_b64: Base64-encoded encrypted item data
        nonce_b64: Base64-encoded nonce
        dek: 32-byte Data Encryption Key
        user_id: User ID for AAD
        item_id: Item ID for AAD
        algo_version: Algorithm version

    Returns:
        Dictionary containing decrypted item fields
    """
    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)
    aad = create_aad(user_id, item_id=item_id, algo_version=algo_version)

    plaintext = aead_decrypt(dek, nonce, ciphertext, aad)
    item_json = plaintext.decode('utf-8')

    return json.loads(item_json)


def secure_zero(data: bytes) -> None:
    """
    Best-effort secure zeroing of sensitive data in memory
    Note: Python's garbage collector makes true secure zeroing difficult
    """
    if isinstance(data, bytes):
        # Overwrite the bytes object's internal buffer
        try:
            import ctypes
            location = id(data) + 32  # Offset to string data in CPython
            size = len(data)
            ctypes.memset(location, 0, size)
        except:
            # Fallback - at least clear the reference
            pass
