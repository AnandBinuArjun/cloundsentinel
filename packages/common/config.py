"""Application configuration loaded strictly from environment variables."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

EnvironmentName = Literal["development", "test", "staging", "production"]


class Settings(BaseSettings):
    """Typed, validated configuration for CloudSentinel services."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    env: EnvironmentName = Field(default="development", alias="CLOUDSENTINEL_ENV")
    version: str = Field(default="1.0.0", alias="CLOUDSENTINEL_VERSION")
    service_name: str = Field(default="cloudsentinel-api", alias="CLOUDSENTINEL_SERVICE_NAME")
    log_level: str = Field(default="INFO", alias="CLOUDSENTINEL_LOG_LEVEL")
    api_host: str = Field(default="127.0.0.1", alias="CLOUDSENTINEL_API_HOST")
    api_port: int = Field(default=8000, ge=1, le=65535, alias="CLOUDSENTINEL_API_PORT")
    cors_origins_raw: str = Field(
        default="http://localhost:5173,http://127.0.0.1:5173",
        alias="CLOUDSENTINEL_CORS_ORIGINS",
    )
    readiness_timeout_seconds: float = Field(
        default=2.0,
        gt=0.1,
        le=15.0,
        alias="CLOUDSENTINEL_READINESS_TIMEOUT_SECONDS",
    )

    # Persistence & Broker
    database_url: str = Field(
        default="postgresql+asyncpg://cloudsentinel@localhost:5432/cloudsentinel",
        alias="DATABASE_URL",
    )
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")
    celery_broker_url: str = Field(
        default="redis://localhost:6379/1",
        alias="CELERY_BROKER_URL",
    )
    celery_result_backend: str = Field(
        default="redis://localhost:6379/2",
        alias="CELERY_RESULT_BACKEND",
    )

    # OIDC / JWT Authentication
    oidc_issuer_url: str = Field(
        default="https://auth.cloudsentinel.local",
        alias="OIDC_ISSUER_URL",
    )
    oidc_jwks_url: str = Field(default="", alias="OIDC_JWKS_URL")
    oidc_audience: str = Field(default="cloudsentinel-api", alias="OIDC_AUDIENCE")
    oidc_leeway_seconds: int = Field(default=30, ge=0, le=120, alias="OIDC_LEEWAY_SECONDS")
    # Non-production local/test HS256 secret (strictly rejected in production).
    dev_jwt_secret: str = Field(default="", alias="CLOUDSENTINEL_DEV_JWT_SECRET")

    # Security & Safety Controls
    rate_limit_requests_per_minute: int = Field(
        default=120,
        ge=10,
        le=10000,
        alias="CLOUDSENTINEL_RATE_LIMIT_RPM",
    )
    live_remediation_enabled: bool = Field(
        default=False,
        alias="CLOUDSENTINEL_LIVE_REMEDIATION_ENABLED",
    )
    remediation_aws_role_arn: str = Field(
        default="",
        alias="CLOUDSENTINEL_REMEDIATION_AWS_ROLE_ARN",
    )

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        normalized = value.strip().upper()
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if normalized not in allowed:
            raise ValueError(f"Unsupported log level: {value}")
        return normalized

    @property
    def cors_origins(self) -> list[str]:
        """Return explicit, non-empty CORS origin allowlist."""
        return [
            origin.strip()
            for origin in self.cors_origins_raw.split(",")
            if origin.strip() and origin.strip() != "*"
        ]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached runtime settings."""
    return Settings()
