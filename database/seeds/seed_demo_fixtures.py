"""Explicitly labeled local demonstration fixture seeder (NEVER for production).

Populates a local development tenant with synthetic AWS & Azure fixture connectors,
runs deterministic assessments, ingests synthetic CloudTrail & Azure Activity Log fixtures,
and prints short-lived local dev JWT tokens for manual console testing.
"""

from __future__ import annotations

import asyncio
import sys
import uuid

from sqlalchemy import select

from apps.api.services.assessment_service import execute_assessment_run, validate_cloud_connection
from detections.engine import (
    evaluate_events,
    normalize_aws_cloudtrail_event,
    normalize_azure_activity_event,
)
from detections.fixtures import (
    SYNTHETIC_AWS_CLOUDTRAIL_EVENTS,
    SYNTHETIC_AZURE_ACTIVITY_EVENTS,
)
from packages.auth.oidc import issue_dev_token
from packages.auth.rbac import AuthContext, Role
from packages.common.config import get_settings
from packages.db.models import (
    CloudConnection,
    DetectionEvent,
    Membership,
    Tenant,
    User,
)
from packages.db.session import create_all_tables, create_db_engine, create_session_factory


async def seed() -> None:
    settings = get_settings()
    if settings.env == "production":
        raise RuntimeError("Refusing to seed synthetic demo fixtures in production environment.")
    if not settings.dev_jwt_secret:
        raise RuntimeError("Set CLOUDSENTINEL_DEV_JWT_SECRET in .env before running local seed.")

    engine = create_db_engine(settings.database_url)
    await create_all_tables(engine)
    session_factory = create_session_factory(engine)

    async with session_factory() as session:
        existing_admin = (
            await session.execute(
                select(User).where(
                    User.oidc_issuer == settings.oidc_issuer_url,
                    User.oidc_subject == "demo-tenant-admin",
                )
            )
        ).scalar_one_or_none()

        if existing_admin is not None:
            existing_membership = (
                await session.execute(
                    select(Membership).where(Membership.user_id == existing_admin.id)
                )
            ).scalar_one()
            existing_analyst = (
                await session.execute(
                    select(User).where(
                        User.oidc_issuer == settings.oidc_issuer_url,
                        User.oidc_subject == "demo-security-analyst",
                    )
                )
            ).scalar_one_or_none()

            admin_jwt = issue_dev_token(
                settings=settings,
                subject=existing_admin.oidc_subject,
                email=existing_admin.email,
                tenant_id=existing_membership.tenant_id,
                display_name=existing_admin.display_name,
            )
            print("Existing synthetic demo tenant:", existing_membership.tenant_id)
            print("Tenant Admin Dev JWT:", admin_jwt)
            if existing_analyst is not None:
                analyst_jwt = issue_dev_token(
                    settings=settings,
                    subject=existing_analyst.oidc_subject,
                    email=existing_analyst.email,
                    tenant_id=existing_membership.tenant_id,
                    display_name=existing_analyst.display_name,
                )
                print("Security Analyst Dev JWT:", analyst_jwt)
            await engine.dispose()
            return

        tenant = Tenant(
            id=uuid.uuid4(),
            name="Acme Security Demo (Synthetic)",
            slug=f"acme-demo-{uuid.uuid4().hex[:6]}",
        )
        admin_user = User(
            id=uuid.uuid4(),
            oidc_issuer=settings.oidc_issuer_url,
            oidc_subject="demo-tenant-admin",
            email="admin@acme-demo.local",
            display_name="Demo Tenant Admin",
        )
        analyst_user = User(
            id=uuid.uuid4(),
            oidc_issuer=settings.oidc_issuer_url,
            oidc_subject="demo-security-analyst",
            email="analyst@acme-demo.local",
            display_name="Demo Security Analyst",
        )
        session.add_all([tenant, admin_user, analyst_user])
        await session.flush()

        session.add_all(
            [
                Membership(
                    tenant_id=tenant.id, user_id=admin_user.id, role=Role.TENANT_ADMIN.value
                ),
                Membership(
                    tenant_id=tenant.id, user_id=analyst_user.id, role=Role.SECURITY_ANALYST.value
                ),
            ]
        )

        aws_conn = CloudConnection(
            tenant_id=tenant.id,
            name="AWS Production (Synthetic Fixture)",
            provider="aws",
            auth_mode="sts_assume_role",
            account_or_subscription_id="123456789012",
            role_arn="arn:aws:iam::123456789012:role/CloudSentinelReadOnlyRole",
            external_id="demo-external-id",
            regions=["us-east-1"],
            data_source="synthetic_fixture",
        )
        azure_conn = CloudConnection(
            tenant_id=tenant.id,
            name="Azure Prod Subscription (Synthetic Fixture)",
            provider="azure",
            auth_mode="managed_identity",
            account_or_subscription_id="00000000-1111-2222-3333-444444444444",
            regions=["eastus"],
            data_source="synthetic_fixture",
        )
        session.add_all([aws_conn, azure_conn])
        await session.commit()

        admin_ctx = AuthContext(
            user_id=admin_user.id,
            tenant_id=tenant.id,
            role=Role.TENANT_ADMIN,
            email=admin_user.email,
            subject=admin_user.oidc_subject,
            request_id="seed-script",
        )
        await validate_cloud_connection(session, auth=admin_ctx, connection=aws_conn)
        await validate_cloud_connection(session, auth=admin_ctx, connection=azure_conn)
        await execute_assessment_run(session, auth=admin_ctx, connection=aws_conn)
        await execute_assessment_run(session, auth=admin_ctx, connection=azure_conn)

        norm_events = [
            normalize_aws_cloudtrail_event(e, data_source="synthetic_fixture")
            for e in SYNTHETIC_AWS_CLOUDTRAIL_EVENTS
        ] + [
            normalize_azure_activity_event(e, data_source="synthetic_fixture")
            for e in SYNTHETIC_AZURE_ACTIVITY_EVENTS
        ]
        for det in evaluate_events(norm_events):
            session.add(
                DetectionEvent(
                    tenant_id=tenant.id,
                    rule_id=det.rule.rule_id,
                    provider=det.event.provider,
                    account_ref=det.event.account_ref,
                    region=det.event.region,
                    event_name=det.event.event_name,
                    actor_identity=det.event.actor_identity,
                    source_ip=det.event.source_ip,
                    severity=det.rule.severity,
                    confidence=det.rule.confidence,
                    mitre_tactic=det.rule.mitre_tactic,
                    mitre_technique=det.rule.mitre_technique,
                    title=det.rule.name,
                    explanation=det.explanation,
                    correlated_event_ids=det.correlated_event_ids,
                    evidence_payload=det.evidence_payload,
                    data_source="synthetic_fixture",
                    event_time=det.event.event_time,
                )
            )
        await session.commit()

        admin_jwt = issue_dev_token(
            settings=settings,
            subject=admin_user.oidc_subject,
            email=admin_user.email,
            tenant_id=tenant.id,
            display_name=admin_user.display_name,
        )
        analyst_jwt = issue_dev_token(
            settings=settings,
            subject=analyst_user.oidc_subject,
            email=analyst_user.email,
            tenant_id=tenant.id,
            display_name=analyst_user.display_name,
        )
        print("Seeded synthetic demo tenant:", tenant.id)
        print("Tenant Admin Dev JWT:", admin_jwt)
        print("Security Analyst Dev JWT:", analyst_jwt)

    await engine.dispose()


if __name__ == "__main__":
    try:
        asyncio.run(seed())
    except Exception as exc:
        print(f"Seed failed: {exc}", file=sys.stderr)
        sys.exit(1)
