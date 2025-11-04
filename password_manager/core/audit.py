"""Tamper-evident audit logging using HMAC chaining."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Optional

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from core.logging_utils import get_security_logger

_logger = get_security_logger()


class TamperEvidentAuditLogger:
    """Persist audit events with chained HMAC integrity protection."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._log_path = self._resolve_log_path()
        self._chain_state_path = self._log_path.with_suffix(".chain")
        self._hmac_key = self._load_hmac_key()
        self._previous_hmac = self._load_previous_hmac()

    @staticmethod
    def _resolve_log_path() -> Path:
        base_dir = Path(getattr(settings, "LOG_DIR", settings.BASE_DIR / "logs"))
        base_dir.mkdir(parents=True, exist_ok=True)
        configured_path = getattr(settings, "AUDIT_LOG_PATH", None)
        audit_path = Path(configured_path) if configured_path else base_dir / "audit.log"
        if not audit_path.parent.exists():
            audit_path.parent.mkdir(parents=True, exist_ok=True)
        return audit_path

    @staticmethod
    def _load_hmac_key() -> bytes:
        configured_key = getattr(settings, "AUDIT_HMAC_KEY", None)
        if configured_key:
            try:
                return base64.b64decode(configured_key)
            except Exception as exc:  # pragma: no cover - configuration error
                raise ImproperlyConfigured("AUDIT_HMAC_KEY must be base64 encoded") from exc

        secret = getattr(settings, "SECRET_KEY", None)
        if not secret:
            _logger.warning(
                "SECRET_KEY not configured; generating ephemeral audit key. "
                "Configure SECRET_KEY and AUDIT_HMAC_KEY in production."
            )
            return os.urandom(32)

        _logger.warning(
            "AUDIT_HMAC_KEY not configured; deriving audit key from SECRET_KEY. "
            "Configure a dedicated random 256-bit key in production."
        )
        return hashlib.sha256(secret.encode("utf-8")).digest()

    def _load_previous_hmac(self) -> Optional[bytes]:
        if not self._chain_state_path.exists():
            return None
        try:
            data = self._chain_state_path.read_text(encoding="utf-8").strip()
            if not data:
                return None
            return base64.b64decode(data)
        except Exception as exc:  # pragma: no cover - corrupted state
            _logger.error("Failed to load audit chain state", extra={"context": {"error": str(exc)}})
            return None

    def _persist_previous(self, hmac_value: bytes) -> None:
        self._chain_state_path.write_text(base64.b64encode(hmac_value).decode("ascii"), encoding="utf-8")

    def log_event(
        self,
        event_type: str,
        *,
        severity: str = "INFO",
        user_id: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Write a tamper-evident log entry and return its HMAC value."""

        timestamp = datetime.now(timezone.utc).isoformat()
        payload: Dict[str, Any] = {
            "timestamp": timestamp,
            "event_type": event_type,
            "severity": severity,
        }
        if user_id is not None:
            payload["user_id"] = user_id
        if metadata:
            payload["metadata"] = metadata

        payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        previous = self._previous_hmac or b""
        digest = hmac.new(self._hmac_key, previous + payload_bytes, hashlib.sha256).digest()

        entry = dict(payload)
        entry["hmac"] = base64.b64encode(digest).decode("ascii")
        entry["previous_hmac"] = base64.b64encode(previous).decode("ascii") if previous else None

        with self._lock:
            with self._log_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(entry, sort_keys=True) + "\n")
            self._previous_hmac = digest
            self._persist_previous(digest)

        return entry["hmac"]

    def log_security_alert(self, event_type: str, *, user_id: Optional[int] = None, metadata: Optional[Dict[str, Any]] = None) -> str:
        """Convenience wrapper for security-relevant alerts."""

        _logger.security_event(f"AUDIT: {event_type}", None, metadata)
        return self.log_event(event_type, severity="ALERT", user_id=user_id, metadata=metadata)


_audit_logger: Optional[TamperEvidentAuditLogger] = None


def get_audit_logger() -> TamperEvidentAuditLogger:
    """Return a singleton audit logger instance."""

    global _audit_logger
    if _audit_logger is None:
        _audit_logger = TamperEvidentAuditLogger()
    return _audit_logger
