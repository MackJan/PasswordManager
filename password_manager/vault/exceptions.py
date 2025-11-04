"""Custom exceptions for the vault domain."""

from typing import Optional


class CryptoError(Exception):
    """Base exception for cryptographic operations."""

    def __init__(self, message: str, *, recoverable: Optional[bool] = None):
        super().__init__(message)
        self.recoverable = recoverable
