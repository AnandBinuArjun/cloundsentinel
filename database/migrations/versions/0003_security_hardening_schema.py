"""Harden PostgreSQL RLS with FORCE ROW LEVEL SECURITY, WITH CHECK, non-owner role, and new operational columns.

Revision ID: 0003_security_hardening_schema
Revises: 0002_postgres_rls_policies
Create Date: 2026-11-23
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003_security_hardening_schema"
down_revision = "0002_postgres_rls_policies"
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


def _add_column_if_missing(
    inspector: sa.Inspector,
    table_name: str,
    column: sa.Column[object],
) -> None:
    existing_cols = {c["name"] for c in inspector.get_columns(table_name)}
    if column.name not in existing_cols:
        op.add_column(table_name, column)


def _create_index_if_missing(
    inspector: sa.Inspector,
    index_name: str,
    table_name: str,
    columns: list[str],
) -> None:
    existing_idx = {idx["name"] for idx in inspector.get_indexes(table_name)}
    if index_name not in existing_idx:
        op.create_index(index_name, table_name, columns)


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    # 1. Assessment orchestration columns (Phase 3)
    _add_column_if_missing(
        inspector, "assessment_runs", sa.Column("job_id", sa.String(length=128), nullable=True)
    )
    _add_column_if_missing(
        inspector,
        "assessment_runs",
        sa.Column("idempotency_key", sa.String(length=128), nullable=True),
    )
    _add_column_if_missing(
        inspector,
        "assessment_runs",
        sa.Column("progress_pct", sa.Integer(), nullable=False, server_default="0"),
    )
    _add_column_if_missing(
        inspector, "assessment_runs", sa.Column("failure_reason", sa.Text(), nullable=True)
    )
    _add_column_if_missing(
        inspector,
        "assessment_runs",
        sa.Column(
            "queued_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )
    _add_column_if_missing(
        inspector,
        "assessment_runs",
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
    )
    _create_index_if_missing(inspector, "ix_assessment_runs_job_id", "assessment_runs", ["job_id"])
    _create_index_if_missing(
        inspector, "ix_assessment_runs_idempotency_key", "assessment_runs", ["idempotency_key"]
    )

    # 2. Detection deduplication column & index (Phase 7)
    _add_column_if_missing(
        inspector,
        "detection_events",
        sa.Column(
            "provider_event_id",
            sa.String(length=128),
            nullable=False,
            server_default="",
        ),
    )
    _create_index_if_missing(
        inspector,
        "ix_detection_events_provider_event_id",
        "detection_events",
        ["provider_event_id"],
    )
    _create_index_if_missing(
        inspector,
        "ix_detection_events_dedup",
        "detection_events",
        ["tenant_id", "provider", "provider_event_id", "rule_id"],
    )

    # 3. Remediation state machine & verification columns (Phase 1)
    _add_column_if_missing(
        inspector,
        "remediation_requests",
        sa.Column("idempotency_key", sa.String(length=128), nullable=True),
    )
    _add_column_if_missing(
        inspector,
        "remediation_requests",
        sa.Column("operation_id", sa.String(length=128), nullable=True),
    )
    _add_column_if_missing(
        inspector,
        "remediation_requests",
        sa.Column("verification_rule_id", sa.String(length=64), nullable=True),
    )
    _add_column_if_missing(
        inspector,
        "remediation_requests",
        sa.Column(
            "verification_status",
            sa.String(length=32),
            nullable=False,
            server_default="unverified",
        ),
    )
    _add_column_if_missing(
        inspector,
        "remediation_requests",
        sa.Column("failure_reason", sa.Text(), nullable=True),
    )
    _add_column_if_missing(
        inspector,
        "remediation_requests",
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
    )
    _add_column_if_missing(
        inspector,
        "remediation_requests",
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
    )
    _create_index_if_missing(
        inspector,
        "ix_remediation_requests_idempotency_key",
        "remediation_requests",
        ["idempotency_key"],
    )

    # 4. PostgreSQL FORCE ROW LEVEL SECURITY, WITH CHECK, and non-owner application role (Phase 2)
    if bind.dialect.name != "postgresql":
        return

    for table in TENANT_SCOPED_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")
        op.execute(f"DROP POLICY IF EXISTS cloudsentinel_tenant_isolation ON {table};")
        op.execute(
            f"""
            CREATE POLICY cloudsentinel_tenant_isolation ON {table}
            FOR ALL
            USING (
                tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            )
            WITH CHECK (
                tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            );
            """
        )

    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cloudsentinel_app') THEN
                CREATE ROLE cloudsentinel_app NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
            END IF;
        END
        $$;
        """
    )
    op.execute("GRANT USAGE ON SCHEMA public TO cloudsentinel_app;")
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO cloudsentinel_app;"
    )
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO cloudsentinel_app;"
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for table in TENANT_SCOPED_TABLES:
            op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY;")

    op.drop_index("ix_remediation_requests_idempotency_key", table_name="remediation_requests")
    op.drop_column("remediation_requests", "verified_at")
    op.drop_column("remediation_requests", "executed_at")
    op.drop_column("remediation_requests", "failure_reason")
    op.drop_column("remediation_requests", "verification_status")
    op.drop_column("remediation_requests", "verification_rule_id")
    op.drop_column("remediation_requests", "operation_id")
    op.drop_column("remediation_requests", "idempotency_key")

    op.drop_index("ix_detection_events_dedup", table_name="detection_events")
    op.drop_index("ix_detection_events_provider_event_id", table_name="detection_events")
    op.drop_column("detection_events", "provider_event_id")

    op.drop_index("ix_assessment_runs_idempotency_key", table_name="assessment_runs")
    op.drop_index("ix_assessment_runs_job_id", table_name="assessment_runs")
    op.drop_column("assessment_runs", "cancelled_at")
    op.drop_column("assessment_runs", "queued_at")
    op.drop_column("assessment_runs", "failure_reason")
    op.drop_column("assessment_runs", "progress_pct")
    op.drop_column("assessment_runs", "idempotency_key")
    op.drop_column("assessment_runs", "job_id")
