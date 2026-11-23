"""Enable PostgreSQL Row-Level Security (RLS) on all tenant-scoped tables.

Revision ID: 0002_postgres_rls_policies
Revises: 0001_initial_schema
Create Date: 2026-11-23
"""

from __future__ import annotations

from alembic import op

revision = "0002_postgres_rls_policies"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None

TENANT_SCOPED_TABLES: tuple[str, ...] = (
    "memberships",
    "cloud_connections",
    "cloud_accounts",
    "assets",
    "assessment_profiles",
    "assessment_runs",
    "assessment_results",
    "findings",
    "finding_history",
    "evidence",
    "detection_events",
    "remediation_requests",
    "remediation_approvals",
    "audit_events",
)


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    for table in TENANT_SCOPED_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        op.execute(
            f"""
            CREATE POLICY cloudsentinel_tenant_isolation ON {table}
            USING (
                tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            );
            """
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    for table in TENANT_SCOPED_TABLES:
        op.execute(f"DROP POLICY IF EXISTS cloudsentinel_tenant_isolation ON {table};")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY;")
