"""Security tests: cross-tenant isolation, RBAC privilege escalation, JWT validation, SoD, SQLi, and rate limits."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from httpx import ASGITransport, AsyncClient

from apps.api.main import create_app
from packages.auth.rbac import Role
from packages.common.config import Settings
from packages.db.models import Membership, Tenant, User
from packages.db.session import create_all_tables, create_db_engine, create_session_factory


async def _setup_two_tenant_app(rate_limit_rpm: int = 120):
    settings = Settings(
        CLOUDSENTINEL_ENV="test",
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
        CLOUDSENTINEL_DEV_JWT_SECRET="security-test-secret-key-minimum-32-chars!!",
        CLOUDSENTINEL_RATE_LIMIT_RPM=rate_limit_rpm,
    )
    engine = create_db_engine(settings.database_url)
    await create_all_tables(engine)
    sf = create_session_factory(engine)

    t_a, t_b = uuid.uuid4(), uuid.uuid4()
    u_a_admin, u_a_ro, u_b_admin = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()

    async with sf() as session:
        session.add_all(
            [
                Tenant(id=t_a, name="Tenant Alpha", slug="alpha"),
                Tenant(id=t_b, name="Tenant Beta", slug="beta"),
                User(
                    id=u_a_admin,
                    oidc_issuer=settings.oidc_issuer_url,
                    oidc_subject="a-admin",
                    email="a@alpha.test",
                    display_name="A Admin",
                ),
                User(
                    id=u_a_ro,
                    oidc_issuer=settings.oidc_issuer_url,
                    oidc_subject="a-ro",
                    email="ro@alpha.test",
                    display_name="A ReadOnly",
                ),
                User(
                    id=u_b_admin,
                    oidc_issuer=settings.oidc_issuer_url,
                    oidc_subject="b-admin",
                    email="b@beta.test",
                    display_name="B Admin",
                ),
                Membership(tenant_id=t_a, user_id=u_a_admin, role=Role.TENANT_ADMIN.value),
                Membership(tenant_id=t_a, user_id=u_a_ro, role=Role.READ_ONLY.value),
                Membership(tenant_id=t_b, user_id=u_b_admin, role=Role.TENANT_ADMIN.value),
            ]
        )
        await session.commit()

    def mint(
        subject: str,
        tenant_id: uuid.UUID,
        exp_minutes: int = 15,
        aud: str | None = None,
        secret: str | None = None,
    ) -> str:
        now = datetime.now(UTC)
        return jwt.encode(
            {
                "iss": settings.oidc_issuer_url,
                "aud": aud or settings.oidc_audience,
                "sub": subject,
                "tenant_id": str(tenant_id),
                "iat": int(now.timestamp()),
                "exp": int((now + timedelta(minutes=exp_minutes)).timestamp()),
            },
            secret or settings.dev_jwt_secret,
            algorithm="HS256",
        )

    app = create_app(settings=settings, db_engine=engine)
    return app, engine, settings, (t_a, t_b), mint


@pytest.mark.security
async def test_invalid_forged_expired_and_wrong_audience_tokens_rejected() -> None:
    app, engine, _settings, (t_a, _t_b), mint = await _setup_two_tenant_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.get("/api/v1/findings")).status_code == 401
        assert (
            await client.get("/api/v1/findings", headers={"Authorization": "Bearer not.a.jwt"})
        ).status_code == 401

        forged = mint("a-admin", t_a, secret="wrong-secret-key-for-forgery-test-123456")
        assert (
            await client.get("/api/v1/findings", headers={"Authorization": f"Bearer {forged}"})
        ).status_code == 401

        expired = mint("a-admin", t_a, exp_minutes=-5)
        assert (
            await client.get("/api/v1/findings", headers={"Authorization": f"Bearer {expired}"})
        ).status_code == 401

        wrong_aud = mint("a-admin", t_a, aud="other-service")
        assert (
            await client.get("/api/v1/findings", headers={"Authorization": f"Bearer {wrong_aud}"})
        ).status_code == 401

    await engine.dispose()


@pytest.mark.security
async def test_cross_tenant_isolation_denies_all_cross_tenant_reads_and_writes() -> None:
    app, engine, _settings, (t_a, t_b), mint = await _setup_two_tenant_app()
    h_a = {"Authorization": f"Bearer {mint('a-admin', t_a)}"}
    h_b = {"Authorization": f"Bearer {mint('b-admin', t_b)}"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Tenant A creates connection & runs assessment
        conn_resp = await client.post(
            "/api/v1/connections",
            headers=h_a,
            json={
                "name": "Alpha AWS",
                "provider": "aws",
                "auth_mode": "sts_assume_role",
                "account_or_subscription_id": "123456789012",
                "role_arn": "arn:aws:iam::123456789012:role/CloudSentinelReadOnlyRole",
                "data_source": "synthetic_fixture",
            },
        )
        assert conn_resp.status_code == 201
        conn_a_id = conn_resp.json()["id"]

        run_resp = await client.post(
            "/api/v1/assessments", headers=h_a, json={"connection_id": conn_a_id}
        )
        assert run_resp.status_code == 201
        finding_a_id = (await client.get("/api/v1/findings", headers=h_a)).json()["items"][0]["id"]

        # Tenant B must see ZERO of Tenant A's resources and receive 404 on direct ID access
        assert (await client.get("/api/v1/connections", headers=h_b)).json()["total"] == 0
        assert (await client.get("/api/v1/findings", headers=h_b)).json()["total"] == 0
        assert (
            await client.get(f"/api/v1/findings/{finding_a_id}", headers=h_b)
        ).status_code == 404
        assert (
            await client.post(f"/api/v1/connections/{conn_a_id}/validate", headers=h_b)
        ).status_code == 404
        assert (
            await client.post("/api/v1/assessments", headers=h_b, json={"connection_id": conn_a_id})
        ).status_code == 404
        assert (
            await client.post(
                "/api/v1/remediations/preview", headers=h_b, json={"finding_id": finding_a_id}
            )
        ).status_code == 404

        # Cross-tenant forged tenant_id claim by user without membership in Tenant A -> 403
        cross_claim = {"Authorization": f"Bearer {mint('b-admin', t_a)}"}
        assert (await client.get("/api/v1/findings", headers=cross_claim)).status_code == 403

    await engine.dispose()


@pytest.mark.security
async def test_rbac_privilege_escalation_and_separation_of_duties() -> None:
    app, engine, _settings, (t_a, _t_b), mint = await _setup_two_tenant_app()
    h_admin = {"Authorization": f"Bearer {mint('a-admin', t_a)}"}
    h_ro = {"Authorization": f"Bearer {mint('a-ro', t_a)}"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Read-only user cannot create connections, export reports, or read audit logs
        assert (
            await client.post(
                "/api/v1/connections",
                headers=h_ro,
                json={
                    "name": "Unauthorized Conn",
                    "provider": "aws",
                    "auth_mode": "sts_assume_role",
                    "account_or_subscription_id": "123456789012",
                    "role_arn": "arn:aws:iam::123456789012:role/ReadOnly",
                },
            )
        ).status_code == 403
        assert (await client.get("/api/v1/audit-events", headers=h_ro)).status_code == 403
        assert (await client.get("/api/v1/reports", headers=h_ro)).status_code == 403

        # Admin sets up finding and proposes remediation -> CANNOT self-approve (Separation of Duties)
        conn_id = (
            await client.post(
                "/api/v1/connections",
                headers=h_admin,
                json={
                    "name": "SoD Test AWS",
                    "provider": "aws",
                    "auth_mode": "sts_assume_role",
                    "account_or_subscription_id": "123456789012",
                    "role_arn": "arn:aws:iam::123456789012:role/ReadOnly",
                    "data_source": "synthetic_fixture",
                },
            )
        ).json()["id"]
        await client.post("/api/v1/assessments", headers=h_admin, json={"connection_id": conn_id})
        finding_id = (await client.get("/api/v1/findings", headers=h_admin)).json()["items"][0][
            "id"
        ]

        prev = await client.post(
            "/api/v1/remediations/preview", headers=h_admin, json={"finding_id": finding_id}
        )
        rem_id = prev.json()["id"]

        self_approve = await client.post(
            f"/api/v1/remediations/{rem_id}/approve",
            headers=h_admin,
            json={"decision": "approved", "comment": "Attempting self-approval"},
        )
        assert self_approve.status_code == 403
        assert "Separation of duties" in self_approve.text

        # SQL injection attempt in search query parameter safely returns 200 with 0 matches
        sqli = await client.get("/api/v1/findings?search=' OR 1=1 --", headers=h_admin)
        assert sqli.status_code == 200 and sqli.json()["total"] == 0

    await engine.dispose()


@pytest.mark.security
async def test_rate_limiter_enforces_http_429() -> None:
    app, engine, _settings, (t_a, _t_b), mint = await _setup_two_tenant_app(rate_limit_rpm=10)
    headers = {"Authorization": f"Bearer {mint('a-admin', t_a)}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        statuses = [
            (await client.get("/api/v1/system/info", headers=headers)).status_code
            for _ in range(12)
        ]
    assert 429 in statuses
    await engine.dispose()
