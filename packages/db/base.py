"""SQLAlchemy 2 declarative base and cross-dialect PostgreSQL/SQLite column types."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase


def utcnow() -> datetime:
    """Return timezone-aware UTC timestamp."""
    return datetime.now(UTC)


JSONBVariant: Any = JSONB().with_variant(JSON(), "sqlite")  # type: ignore[no-untyped-call]
UTCTimestamp: Any = DateTime(timezone=True)


class Base(DeclarativeBase):
    """Base ORM class for all CloudSentinel relational entities."""
