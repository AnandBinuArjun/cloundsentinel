"""End-to-end integration test exercising Milestones 1 through 8 across FastAPI + SQLAlchemy 2."""

from __future__ import annotations

import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from apps.api.main import create_app
from detections.fixtures import SYNTHETIC_AWS_CLOUDTRAIL_EVENTS, SYNTHETIC_AZURE_ACTIVITY_EVENTS
from packages.auth.oidc import issue_dev_token
from packages.auth.rbac import Role
from packages.common.config import Settings
from packages.db.models import Membership, Tenant, User
from packages.db.session import create_all_tables, create_db_engine, create_session_factory


@pytest.mark.integration
async def test_full_cspm_detection_compliance_reporting_and_remediation_lifecycle() -> None:
    settings = Settings(
        CLOUDSENTINEL_ENV="test",
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
        CLOUDSENTINEL_DEV_JWT_SECRET="test-only-signing-secret-at-least-32-chars!!",
    )
    engine = create_db_engine(settings.database_url)
    await create_all_tables(engine)
    session_factory = create_session_factory(engine)

    tenant_id = uuid.uuid4()
    admin_id = uuid.uuid4()
    analyst_id = uuid.uuid4()

    async with session_factory() as session:
        session.add_all(
            [
                Tenant(id=tenant_id, name="Acme Corp", slug="acme-corp"),
                User(
                    id=admin_id,
                    oidc_issuer=settings.oidc_issuer_url,
                    oidc_subject="sub-admin",
                    email="admin@acme.test",
                    display_name="Tenant Admin",
                ),
                User(
                    id=analyst_id,
                    oidc_issuer=settings.oidc_issuer_url,
                    oidc_subject="sub-analyst",
                    email="analyst@acme.test",
                    display_name="Security Analyst",
                ),
                Membership(tenant_id=tenant_id, user_id=admin_id, role=Role.TENANT_ADMIN.value),
                Membership(
                    tenant_id=tenant_id, user_id=analyst_id, role=Role.SECURITY_ANALYST.value
                ),
            ]
        )
        await session.commit()

    admin_token = issue_dev_token(
        settings=settings, subject="sub-admin", email="admin@acme.test", tenant_id=tenant_id
    )
    analyst_token = issue_dev_token(
        settings=settings, subject="sub-analyst", email="analyst@acme.test", tenant_id=tenant_id
    )
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}

    app = create_app(settings=settings, db_engine=engine)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Auth introspection
        me = await client.get("/api/v1/auth/me", headers=admin_headers)
        assert me.status_code == 200
        assert me.json()["role"] == "tenant_admin"

        # 2. Onboard & validate AWS + Azure connectors (explicitly synthetic_fixture)
        aws_create = await client.post(
            "/api/v1/connections",
            headers=admin_headers,
            json={
                "name": "AWS Prod Fixture",
                "provider": "aws",
                "auth_mode": "sts_assume_role",
                "account_or_subscription_id": "123456789012",
                "role_arn": "arn:aws:iam::123456789012:role/CloudSentinelReadOnlyRole",
                "external_id": "ext-acme-1",
                "regions": ["us-east-1"],
                "data_source": "synthetic_fixture",
            },
        )
        assert aws_create.status_code == 201
        aws_conn_id = aws_create.json()["id"]

        az_create = await client.post(
            "/api/v1/connections",
            headers=admin_headers,
            json={
                "name": "Azure Prod Fixture",
                "provider": "azure",
                "auth_mode": "managed_identity",
                "account_or_subscription_id": "00000000-1111-2222-3333-444444444444",
                "regions": ["eastus"],
                "data_source": "synthetic_fixture",
            },
        )
        assert az_create.status_code == 201
        az_conn_id = az_create.json()["id"]

        assert (
            await client.post(f"/api/v1/connections/{aws_conn_id}/validate", headers=admin_headers)
        ).json()["valid"] is True
        assert (
            await client.post(f"/api/v1/connections/{az_conn_id}/validate", headers=admin_headers)
        ).json()["valid"] is True

        # 3. Trigger AWS & Azure assessments
        run_aws = await client.post(
            "/api/v1/assessments", headers=analyst_headers, json={"connection_id": aws_conn_id}
        )
        run_az = await client.post(
            "/api/v1/assessments", headers=analyst_headers, json={"connection_id": az_conn_id}
        )
        assert run_aws.status_code == 202 and run_aws.json()["checks_failed"] > 0
        assert run_az.status_code == 202 and run_az.json()["checks_failed"] > 0

        # 4. Assets, Findings, Detail/Evidence & Identity Analysis
        assets = await client.get("/api/v1/assets", headers=analyst_headers)
        assert assets.status_code == 200 and assets.json()["total"] >= 10

        findings = await client.get("/api/v1/findings", headers=analyst_headers)
        assert findings.status_code == 200 and findings.json()["total"] >= 10
        top_finding_id = findings.json()["items"][0]["id"]

        detail = await client.get(f"/api/v1/findings/{top_finding_id}", headers=analyst_headers)
        assert detail.status_code == 200
        assert len(detail.json()["evidence"]) >= 1

        identity = await client.get("/api/v1/identity/analysis", headers=analyst_headers)
        assert identity.status_code == 200
        assert len(identity.json()["reports"]) == 2

        # 5. Ingest CloudTrail & Azure Activity Log detections
        ing_aws = await client.post(
            "/api/v1/detections/ingest",
            headers=analyst_headers,
            json={
                "provider": "aws",
                "events": SYNTHETIC_AWS_CLOUDTRAIL_EVENTS,
                "data_source": "synthetic_fixture",
            },
        )
        ing_az = await client.post(
            "/api/v1/detections/ingest",
            headers=analyst_headers,
            json={
                "provider": "azure",
                "events": SYNTHETIC_AZURE_ACTIVITY_EVENTS,
                "data_source": "synthetic_fixture",
            },
        )
        assert ing_aws.status_code == 201 and ing_aws.json()["detections_triggered"] == 3
        assert ing_az.status_code == 201 and ing_az.json()["detections_triggered"] == 2

        det_id = ing_aws.json()["items"][0]["id"]
        disp = await client.patch(
            f"/api/v1/detections/{det_id}",
            headers=analyst_headers,
            json={
                "disposition": "true_positive",
                "reason": "Confirmed unauthorized StopLogging event.",
            },
        )
        assert disp.status_code == 200 and disp.json()["disposition"] == "true_positive"

        # 6. Compliance & Dashboard summary
        comp = await client.get("/api/v1/compliance", headers=analyst_headers)
        assert comp.status_code == 200 and len(comp.json()["frameworks"]) == 4

        dash = await client.get("/api/v1/dashboard/summary", headers=analyst_headers)
        assert dash.status_code == 200
        assert dash.json()["contains_synthetic_fixtures"] is True
        assert dash.json()["connections"]["total"] == 2
        assert dash.json()["findings"]["open"] >= 10

        # 7. Safe Remediation Lifecycle (Analyst proposes -> Admin approves -> Admin executes dry-run)
        prev = await client.post(
            "/api/v1/remediations/preview",
            headers=analyst_headers,
            json={"finding_id": top_finding_id},
        )
        assert prev.status_code == 201
        rem_id = prev.json()["id"]
        assert prev.json()["stage"] == "previewed"

        appr = await client.post(
            f"/api/v1/remediations/{rem_id}/approve",
            headers=admin_headers,
            json={"decision": "approved", "comment": "Approved after impact review."},
        )
        assert appr.status_code == 200 and appr.json()["stage"] == "approved"

        exec_resp = await client.post(
            f"/api/v1/remediations/{rem_id}/execute",
            headers=admin_headers,
            json={"confirm_live": False},
        )
        assert exec_resp.status_code == 200
        assert exec_resp.json()["stage"] == "executed_unverified"
        assert exec_resp.json()["execution_mode"] == "dry_run"
        assert exec_resp.json()["verification_status"] == "dry_run_simulated"

        # Verify dry-run NEVER resolves the real finding
        after_dry_run_finding = await client.get(
            f"/api/v1/findings/{top_finding_id}", headers=analyst_headers
        )
        assert after_dry_run_finding.json()["finding"]["status"] == "open"

        # 8. Export JSON, CSV, and PDF reports (including external-sharing redaction)
        rep_json = await client.get(
            "/api/v1/reports?report_type=posture&format=json&redact=true", headers=analyst_headers
        )
        assert rep_json.status_code == 200
        assert "123456789012" not in rep_json.text
        assert "[REDACTED-ACCOUNT]" in rep_json.text

        rep_csv = await client.get(
            "/api/v1/reports?report_type=posture&format=csv", headers=analyst_headers
        )
        assert rep_csv.status_code == 200 and "rule_id" in rep_csv.text

        rep_pdf = await client.get(
            "/api/v1/reports?report_type=posture&format=pdf&redact=true", headers=analyst_headers
        )
        assert rep_pdf.status_code == 200
        assert rep_pdf.content.startswith(b"%PDF-")

        # 9. Immutable Audit Trail
        audit = await client.get("/api/v1/audit-events", headers=admin_headers)
        assert audit.status_code == 200
        actions = {ev["action"] for ev in audit.json()["items"]}
        assert {
            "connection.created",
            "assessment.completed",
            "remediation.previewed",
            "remediation.approved",
            "remediation.executed",
            "report.exported",
        }.issubset(actions)

    await engine.dispose()
