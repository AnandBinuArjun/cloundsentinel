"""Initial CloudSentinel multi-tenant schema (all 21 core entities).

Revision ID: 0001_initial_schema
Revises: None
Create Date: 2026-11-23
"""

from __future__ import annotations

from alembic import op

from packages.db import models as _models  # noqa: F401
from packages.db.base import Base

revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind, checkfirst=True)


def downgrade() -> None:
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind, checkfirst=True)
