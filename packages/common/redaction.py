"""Sensitive field and credential redaction utilities."""

from __future__ import annotations

import re
from typing import Any

REDACTED_VALUE = "[REDACTED]"

_SENSITIVE_KEY_FRAGMENTS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "cookie",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "client_secret",
    "session_key",
    "credential",
)

_URL_CREDENTIALS_PATTERN = re.compile(r"(://[^:/@\s]+:)([^@\s]+)(@)")


def is_sensitive_key(key: str) -> bool:
    """Return True if a dictionary key name likely holds sensitive material."""
    lowered = key.strip().lower()
    return any(fragment in lowered for fragment in _SENSITIVE_KEY_FRAGMENTS)


def redact_string(value: str) -> str:
    """Mask inline password segments in connection URLs."""
    return _URL_CREDENTIALS_PATTERN.sub(rf"\1{REDACTED_VALUE}\3", value)


def redact_data(payload: Any) -> Any:
    """Recursively redact sensitive keys and credential-bearing URLs."""
    if isinstance(payload, dict):
        return {
            k: REDACTED_VALUE if isinstance(k, str) and is_sensitive_key(k) else redact_data(v)
            for k, v in payload.items()
        }
    if isinstance(payload, list):
        return [redact_data(item) for item in payload]
    if isinstance(payload, tuple):
        return tuple(redact_data(item) for item in payload)
    if isinstance(payload, str):
        return redact_string(payload)
    return payload
