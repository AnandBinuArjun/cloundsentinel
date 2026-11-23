"""Unit tests for configuration, redaction, contracts, and worker ping."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from apps.worker.celery_app import ping
from packages.assessment import CheckStatus
from packages.common.config import Settings
from packages.common.redaction import REDACTED_VALUE, redact_data, redact_string


@pytest.mark.unit
def test_settings_strip_wildcard_cors_origin() -> None:
    settings = Settings(CLOUDSENTINEL_CORS_ORIGINS="http://localhost:5173, *, https://sec.example")
    assert settings.cors_origins == ["http://localhost:5173", "https://sec.example"]


@pytest.mark.unit
def test_settings_reject_invalid_log_level() -> None:
    with pytest.raises(ValidationError):
        Settings(CLOUDSENTINEL_LOG_LEVEL="VERBOSE_INVALID")


@pytest.mark.unit
def test_redact_data_masks_sensitive_keys_and_urls() -> None:
    raw = {
        "tenant": "acme",
        "aws_secret_access_key": "super-secret-value",
        "nested": {
            "authorization": "Bearer eyJ123",
            "db_url": "postgresql+asyncpg://user:mySecretPass@db.internal:5432/app",
            "safe": "visible",
        },
    }
    redacted = redact_data(raw)
    assert redacted["tenant"] == "acme"
    assert redacted["aws_secret_access_key"] == REDACTED_VALUE
    assert redacted["nested"]["authorization"] == REDACTED_VALUE
    assert "mySecretPass" not in redacted["nested"]["db_url"]
    assert REDACTED_VALUE in redacted["nested"]["db_url"]
    assert redacted["nested"]["safe"] == "visible"


@pytest.mark.unit
def test_redact_string_preserves_plain_text() -> None:
    assert redact_string("normal message without creds") == "normal message without creds"


@pytest.mark.unit
def test_check_status_contract_values() -> None:
    assert {status.value for status in CheckStatus} == {
        "PASS",
        "FAIL",
        "NOT_ASSESSED",
        "ERROR",
    }


@pytest.mark.unit
def test_worker_ping_task_returns_pong() -> None:
    result = ping()
    assert result["status"] == "pong"
    assert result["service"] == "cloudsentinel-worker"
    assert result["timestamp"].endswith("Z")
