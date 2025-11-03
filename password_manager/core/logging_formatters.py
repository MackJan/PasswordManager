"""Custom logging formatters used across the project."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict


class JSONLogFormatter(logging.Formatter):
    """Render log records as structured JSON."""

    def __init__(self, *, ensure_ascii: bool = False, datefmt: str | None = None):
        super().__init__(datefmt=datefmt)
        self.ensure_ascii = ensure_ascii

    def format(self, record: logging.LogRecord) -> str:
        log_record: Dict[str, Any] = {
            "timestamp": self._format_timestamp(record),
            "level": record.levelname,
            "logger": record.name,
            "module": record.module,
            "message": record.getMessage(),
            "user_id": getattr(record, "user_id", "anonymous"),
            "ip": getattr(record, "ip", "unknown"),
            "request_id": getattr(record, "request_id", "unknown"),
            "method": getattr(record, "http_method", "UNKNOWN"),
            "path": getattr(record, "path", ""),
            "user_agent": getattr(record, "user_agent", ""),
            "referer": getattr(record, "referer", ""),
            "host": getattr(record, "host", ""),
        }

        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)

        if record.stack_info:
            log_record["stack"] = self.formatStack(record.stack_info)

        return json.dumps(log_record, ensure_ascii=self.ensure_ascii)

    def _format_timestamp(self, record: logging.LogRecord) -> str:
        dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
        if self.datefmt:
            return dt.strftime(self.datefmt)
        return dt.isoformat()

