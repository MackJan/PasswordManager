import base64
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_VERSION_PREFIX = 'v2:'
_NONCE_SIZE = 12


def _normalize_key(key):
    if key is None:
        raise ValueError('Encryption key is required')
    if isinstance(key, str):
        key_bytes = key.encode('utf-8')
    else:
        key_bytes = key
    if len(key_bytes) not in (16, 24, 32):
        raise ValueError('Encryption key must be 128, 192, or 256 bits long')
    return key_bytes


def encrypt_data(plain_text, secret_key):
    """Encrypt plain text with AES-GCM and integrity protection."""
    if plain_text in (None, ''):
        return None
    key = _normalize_key(secret_key)
    nonce = os.urandom(_NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plain_text.encode('utf-8'), None)
    payload = base64.urlsafe_b64encode(nonce + ciphertext).decode('ascii')
    return f"{_VERSION_PREFIX}{payload}"


def decrypt_data(encrypted_text, secret_key, fallback_key=None):
    """Decrypt data supporting both the new AEAD format and legacy CFB data."""
    if not encrypted_text:
        return None

    if encrypted_text.startswith(_VERSION_PREFIX):
        key = _normalize_key(secret_key)
        decoded = base64.urlsafe_b64decode(encrypted_text[len(_VERSION_PREFIX):])
        nonce, ciphertext = decoded[:_NONCE_SIZE], decoded[_NONCE_SIZE:]
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')

    legacy_key = fallback_key or secret_key
    key = _normalize_key(legacy_key)
    encrypted_bytes = base64.urlsafe_b64decode(encrypted_text)
    iv = encrypted_bytes[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_bytes[16:]) + decryptor.finalize()
    return decrypted_data.decode('utf-8')
