"""Runtime security controls such as decrypt rate monitoring."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from threading import Lock
from typing import Deque, Dict

from django.conf import settings

from core.logging_utils import get_security_logger

_logger = get_security_logger()


class DecryptRateMonitor:
    """Detect anomalous decrypt activity to surface potential abuse."""

    def __init__(self, threshold: int, window_seconds: int) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds
        self._events: Dict[int, Deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def record(self, user_id: int) -> bool:
        """Record a decrypt event and return True if rate exceeds threshold."""

        now = time.monotonic()
        with self._lock:
            history = self._events[user_id]
            history.append(now)
            cutoff = now - self.window_seconds
            while history and history[0] < cutoff:
                history.popleft()
            if len(history) > self.threshold:
                _logger.security_event(
                    "Decrypt rate threshold exceeded",
                    extra_data={"user_id": user_id, "count": len(history)},
                )
                return True
        return False


_monitor_instance: DecryptRateMonitor | None = None


def get_decrypt_rate_monitor() -> DecryptRateMonitor:
    """Return a singleton decrypt rate monitor."""

    global _monitor_instance
    if _monitor_instance is None:
        threshold = int(getattr(settings, "VAULT_DECRYPT_RATE_THRESHOLD", 120))
        window = int(getattr(settings, "VAULT_DECRYPT_RATE_WINDOW", 60))
        _monitor_instance = DecryptRateMonitor(threshold, window)
    return _monitor_instance
