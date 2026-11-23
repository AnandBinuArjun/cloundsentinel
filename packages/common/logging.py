"""Structured JSON logging with request correlation and redaction."""

from __future__ import annotations

import contextvars
import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

from packages.common.redaction import redact_data, redact_string

request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")


class JsonLogFormatter(logging.Formatter):
    """Emit safe, single-line JSON logs with request correlation."""

    def format(self, record: logging.LogRecord) -> str:
        log_payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_string(record.getMessage()),
            "request_id": request_id_ctx.get(),
        }
        extra_context = getattr(record, "context", None)
        if isinstance(extra_context, dict):
            log_payload["context"] = redact_data(extra_context)
        if record.exc_info and record.exc_info[0] is not None:
            log_payload["exception_type"] = record.exc_info[0].__name__
        return json.dumps(log_payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    """Configure root logger for structured JSON output."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonLogFormatter())

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(level.upper())
