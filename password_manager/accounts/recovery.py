"""Utilities for generating and hashing MFA recovery codes."""

import hashlib
import secrets
import string
from typing import Iterable, List

CODE_CHARSET = string.ascii_uppercase + string.digits
REQUIRED_LENGTH = 8


def normalize_recovery_code(code: str) -> str:
    """Normalize a user-provided code into XXXX-XXXX format."""
    if not code:
        return ''
    cleaned = ''.join(ch for ch in code.upper() if ch.isalnum())[:REQUIRED_LENGTH]
    if len(cleaned) < REQUIRED_LENGTH:
        return cleaned
    return f"{cleaned[:4]}-{cleaned[4:]}"


def _seed_to_bytes(seed) -> bytes:
    if isinstance(seed, bytes):
        return seed
    if isinstance(seed, str):
        try:
            return bytes.fromhex(seed)
        except ValueError:
            return seed.encode('utf-8')
    raise TypeError('Seed must be bytes or hex string')


def hash_recovery_code(seed, code: str) -> str:
    """Return the SHA-256 hash of the normalized code combined with the seed."""
    normalized = normalize_recovery_code(code)
    if len(normalized.replace('-', '')) != REQUIRED_LENGTH:
        raise ValueError('Recovery code must contain 8 alphanumeric characters')
    seed_bytes = _seed_to_bytes(seed)
    digest = hashlib.sha256(seed_bytes + normalized.encode('utf-8')).hexdigest()
    return digest


def generate_recovery_codes(count: int = 10) -> List[str]:
    """Generate human-readable recovery codes."""
    codes = []
    for _ in range(count):
        raw = ''.join(secrets.choice(CODE_CHARSET) for _ in range(REQUIRED_LENGTH))
        codes.append(f"{raw[:4]}-{raw[4:]}")
    return codes


def get_recovery_codes_data(codes: Iterable[str]) -> dict:
    """Return the data structure persisted by allauth for recovery codes."""
    seed = secrets.token_bytes(32)
    hashed_codes = [hash_recovery_code(seed, code) for code in codes]
    return {
        'seed': seed.hex(),
        'unused_codes': hashed_codes,
        'used_mask': 0,
    }


def _looks_like_hash(value: str) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in string.hexdigits for ch in value)


def ensure_hashed_recovery_codes(data: dict) -> bool:
    """Ensure stored codes are hashed, mutating the provided data if needed."""
    if not data or 'unused_codes' not in data:
        return False
    seed = data.get('seed')
    if not seed:
        return False
    unused_codes = data.get('unused_codes') or []
    if not unused_codes:
        return False
    if all(_looks_like_hash(code) for code in unused_codes):
        return False
    seed_bytes = _seed_to_bytes(seed)
    data['unused_codes'] = [hash_recovery_code(seed_bytes, code) for code in unused_codes]
    return True
