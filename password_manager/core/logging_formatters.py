"""Custom logging formatters for structured logging output."""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict


class StructuredJSONFormatter(logging.Formatter):
    """Format log records as structured JSON."""

    def format(self, record: logging.LogRecord) -> str:  # pragma: no cover - exercised via logging
        log_record: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "module": record.module,
            "message": record.getMessage(),
        }

        for attr, key in (
            ("user_id", "user_id"),
            ("user_email", "user_email"),
            ("ip", "ip"),
            ("path", "path"),
            ("http_method", "http_method"),
            ("status_code", "status_code"),
        ):
            value = getattr(record, attr, None)
            if value not in (None, ""):
                log_record[key] = value

        context = getattr(record, "context", None)
        if isinstance(context, dict):
            for key, value in context.items():
                if key in log_record and log_record[key] == value:
                    continue
                if key in log_record and log_record[key] != value:
                    log_record[f"context_{key}"] = value
                else:
                    log_record[key] = value

        if record.exc_info:
            log_record["exc_info"] = self.formatException(record.exc_info)
        if record.stack_info:
            log_record["stack_info"] = self.formatStack(record.stack_info)

        return json.dumps(log_record, default=str)
