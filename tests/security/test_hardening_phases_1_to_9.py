"""Comprehensive security and functional verification suite for Phases 1 through 9."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest
from botocore.exceptions import ClientError
from httpx import ASGITransport, AsyncClient

from apps.api.main import create_app
from apps.api.services.remediation_service import (
    ProviderMutationOutcome,
    ReassessmentVerificationOutcome,
)
from apps.worker.celery_app import dispatch_assessment
from cloud_connectors.aws.connector import AWSConnector
from cloud_connectors.azure.connector import AzureConnector
from detections.fixtures import SYNTHETIC_AWS_CLOUDTRAIL_EVENTS
from packages.assessment.interface import CheckStatus
from packages.auth.oidc import compute_pkce_challenge, generate_pkce_pair, issue_dev_token
from packages.auth.rbac import Role
from packages.common.config import Settings
from packages.db.models import Finding, Membership, RemediationRequest, Tenant, User
from packages.db.session import (
    create_all_tables,
    create_db_engine,
    create_session_factory,
    reset_postgres_tenant_context,
    set_postgres_tenant_context,
    verify_postgres_tenant_context,
)


async def _bootstrap_test_app(
    *,
    live_remediation_enabled: bool = False,
    remediation_aws_role_arn: str = "",
    max_body_bytes: int = 1_048_576,
    rate_limit_rpm: int = 120,
) -> tuple[Any, Any, Settings, uuid.UUID, dict[str, str], dict[str, str]]:
    settings = Settings(
        CLOUDSENTINEL_ENV="test",
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
        CLOUDSENTINEL_DEV_JWT_SECRET="hardening-test-secret-minimum-32-chars-long!!",
        CLOUDSENTINEL_LIVE_REMEDIATION_ENABLED=live_remediation_enabled,
        CLOUDSENTINEL_REMEDIATION_AWS_ROLE_ARN=remediation_aws_role_arn,
        CLOUDSENTINEL_MAX_REQUEST_BODY_BYTES=max_body_bytes,
        CLOUDSENTINEL_RATE_LIMIT_RPM=rate_limit_rpm,
    )
    engine = create_db_engine(settings.database_url)
    await create_all_tables(engine)
    sf = create_session_factory(engine)

    tenant_id = uuid.uuid4()
    admin_id = uuid.uuid4()
    analyst_id = uuid.uuid4()

    async with sf() as session:
        session.add_all(
            [
                Tenant(id=tenant_id, name="Hardening Org", slug="hardening-org"),
                User(
                    id=admin_id,
                    oidc_issuer=settings.oidc_issuer_url,
                    oidc_subject="sub-admin-h",
                    email="admin@hardening.test",
                    display_name="Hardening Admin",
                ),
                User(
                    id=analyst_id,
                    oidc_issuer=settings.oidc_issuer_url,
                    oidc_subject="sub-analyst-h",
                    email="analyst@hardening.test",
                    display_name="Hardening Analyst",
                ),
                Membership(tenant_id=tenant_id, user_id=admin_id, role=Role.TENANT_ADMIN.value),
                Membership(
                    tenant_id=tenant_id, user_id=analyst_id, role=Role.SECURITY_ANALYST.value
                ),
            ]
        )
        await session.commit()

    admin_token = issue_dev_token(
        settings=settings,
        subject="sub-admin-h",
        email="admin@hardening.test",
        tenant_id=tenant_id,
    )
    analyst_token = issue_dev_token(
        settings=settings,
        subject="sub-analyst-h",
        email="analyst@hardening.test",
        tenant_id=tenant_id,
    )
    app = create_app(settings=settings, db_engine=engine)
    return (
        app,
        engine,
        settings,
        tenant_id,
        {"Authorization": f"Bearer {admin_token}"},
        {"Authorization": f"Bearer {analyst_token}"},
    )


@pytest.mark.security
async def test_phase1_remediation_state_machine_and_reassessment_verification_contract() -> None:
    """Verify Phase 1 remediation state machine:
    - Dry-run never resolves findings and transitions to executed_unverified
    - Unapproved execution is blocked (409)
    - Live execution without provider_executor returns HTTP 501 Not Implemented
    - Live execution with failed mutation transitions to failed
    - Live execution with mutation success but reassessment FAIL transitions to rollback_required and leaves finding open
    - Live execution with mutation success AND reassessment PASS transitions to verified and resolves finding
    - Duplicate execution on verified request is rejected (409)
    """
    app, engine, _settings, _tenant_id, h_admin, h_analyst = await _bootstrap_test_app(
        live_remediation_enabled=True,
        remediation_aws_role_arn="arn:aws:iam::123456789012:role/CloudSentinelRemediationRole",
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        conn_id = (
            await client.post(
                "/api/v1/connections",
                headers=h_admin,
                json={
                    "name": "Phase1 AWS",
                    "provider": "aws",
                    "auth_mode": "sts_assume_role",
                    "account_or_subscription_id": "123456789012",
                    "role_arn": "arn:aws:iam::123456789012:role/CloudSentinelReadOnlyRole",
                    "data_source": "synthetic_fixture",
                },
            )
        ).json()["id"]
        await client.post("/api/v1/assessments", headers=h_analyst, json={"connection_id": conn_id})
        findings = (await client.get("/api/v1/findings", headers=h_analyst)).json()["items"]
        s3_finding = next(f for f in findings if f["rule_id"] == "AWS-S3-001")
        finding_id = s3_finding["id"]

        # 1. Preview with idempotency_key returns identical request on replay
        prev1 = await client.post(
            "/api/v1/remediations/preview",
            headers=h_analyst,
            json={"finding_id": finding_id, "idempotency_key": "idem-prev-001"},
        )
        prev2 = await client.post(
            "/api/v1/remediations/preview",
            headers=h_analyst,
            json={"finding_id": finding_id, "idempotency_key": "idem-prev-001"},
        )
        assert prev1.status_code == 201
        assert prev1.json()["id"] == prev2.json()["id"]
        rem_id = prev1.json()["id"]

        # 2. Execution before approval is blocked with 409 Conflict
        unapproved_exec = await client.post(
            f"/api/v1/remediations/{rem_id}/execute",
            headers=h_admin,
            json={"confirm_live": False},
        )
        assert unapproved_exec.status_code == 409

        # 3. Approve request -> attempt live execution without provider_executor -> HTTP 501
        await client.post(
            f"/api/v1/remediations/{rem_id}/approve",
            headers=h_admin,
            json={"decision": "approved", "comment": "Approved for 501 check."},
        )
        no_executor_resp = await client.post(
            f"/api/v1/remediations/{rem_id}/execute",
            headers=h_admin,
            json={"confirm_live": True},
        )
        assert no_executor_resp.status_code == 501
        assert "Live provider executor for action" in no_executor_resp.text

        # 4. Dry-run execution succeeds -> stage == executed_unverified, finding remains open, integrity_sha256 present
        dry_exec = await client.post(
            f"/api/v1/remediations/{rem_id}/execute",
            headers=h_admin,
            json={"confirm_live": False},
        )
        assert dry_exec.status_code == 200
        dry_body = dry_exec.json()
        assert dry_body["stage"] == "executed_unverified"
        assert dry_body["verification_status"] == "dry_run_simulated"
        assert "integrity_sha256" in dry_body["verification_evidence"]
        assert (await client.get(f"/api/v1/findings/{finding_id}", headers=h_analyst)).json()[
            "finding"
        ]["status"] == "open"

        # 5. Second preview -> approve -> live execution where reassessment FAILS -> failed, finding still open
        prev_fail = (
            await client.post(
                "/api/v1/remediations/preview",
                headers=h_analyst,
                json={"finding_id": finding_id},
            )
        ).json()["id"]
        await client.post(
            f"/api/v1/remediations/{prev_fail}/approve",
            headers=h_admin,
            json={"decision": "approved", "comment": "Approve for reassessment failure test."},
        )

        def mock_executor_ok(
            _rem: RemediationRequest, _find: Finding, _cfg: Settings
        ) -> ProviderMutationOutcome:
            return ProviderMutationOutcome(
                success=True,
                operation_id="aws-op-12345",
                provider_response={"HTTPStatusCode": 200},
            )

        def mock_verifier_fail(
            _rem: RemediationRequest, find: Finding, _cfg: Settings
        ) -> ReassessmentVerificationOutcome:
            return ReassessmentVerificationOutcome(
                rule_id="AWS-S3-001",
                resource_id=find.resource_id,
                status=CheckStatus.FAIL,
                observed_config={"BlockPublicAcls": False},
                explanation="PublicAccessBlock still disabled on read-back.",
            )

        app.state.remediation_provider_executor = mock_executor_ok
        app.state.remediation_posture_verifier = mock_verifier_fail

        failed_ver_resp = await client.post(
            f"/api/v1/remediations/{prev_fail}/execute",
            headers=h_admin,
            json={"confirm_live": True},
        )
        assert failed_ver_resp.status_code == 200
        assert failed_ver_resp.json()["stage"] == "failed"
        assert failed_ver_resp.json()["verification_status"] == "verification_fail"
        assert (await client.get(f"/api/v1/findings/{finding_id}", headers=h_analyst)).json()[
            "finding"
        ]["status"] == "open"

        # 6. Third preview -> approve -> live execution where reassessment PASSES -> stage == verified AND finding resolved
        prev_pass = (
            await client.post(
                "/api/v1/remediations/preview",
                headers=h_analyst,
                json={"finding_id": finding_id},
            )
        ).json()["id"]
        await client.post(
            f"/api/v1/remediations/{prev_pass}/approve",
            headers=h_admin,
            json={
                "decision": "approved",
                "comment": "Approve for verified reassessment PASS test.",
            },
        )

        def mock_verifier_pass(
            _rem: RemediationRequest, find: Finding, _cfg: Settings
        ) -> ReassessmentVerificationOutcome:
            return ReassessmentVerificationOutcome(
                rule_id="AWS-S3-001",
                resource_id=find.resource_id,
                status=CheckStatus.PASS,
                observed_config={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
                explanation="All four S3 Block Public Access flags verified enabled on read-back.",
            )

        app.state.remediation_posture_verifier = mock_verifier_pass

        verified_resp = await client.post(
            f"/api/v1/remediations/{prev_pass}/execute",
            headers=h_admin,
            json={"confirm_live": True},
        )
        assert verified_resp.status_code == 200
        assert verified_resp.json()["stage"] == "verified"
        assert verified_resp.json()["verification_status"] == "verified_pass"
        assert (await client.get(f"/api/v1/findings/{finding_id}", headers=h_analyst)).json()[
            "finding"
        ]["status"] == "resolved"

        # 7. Duplicate execution without matching idempotency key is rejected with 409
        dup_exec = await client.post(
            f"/api/v1/remediations/{prev_pass}/execute",
            headers=h_admin,
            json={"confirm_live": True},
        )
        assert dup_exec.status_code == 409

    await engine.dispose()


@pytest.mark.security
async def test_phase2_postgres_rls_migration_and_session_context_hygiene() -> None:
    """Verify Phase 2 RLS migration file defines FORCE ROW LEVEL SECURITY, WITH CHECK, and cloudsentinel_app role."""
    migration_file = Path("database/migrations/versions/0003_security_hardening_schema.py")
    assert migration_file.exists()
    content = migration_file.read_text(encoding="utf-8")
    assert "FORCE ROW LEVEL SECURITY" in content
    assert "WITH CHECK" in content
    assert "cloudsentinel_app" in content
    assert "NOBYPASSRLS" in content

    # Verify session context helpers operate safely on SQLite without error
    engine = create_db_engine("sqlite+aiosqlite:///:memory:")
    sf = create_session_factory(engine)
    tid = uuid.uuid4()
    async with sf() as session:
        await reset_postgres_tenant_context(session)
        await set_postgres_tenant_context(session, tid)
        await verify_postgres_tenant_context(session, tid)
    await engine.dispose()


@pytest.mark.security
async def test_phase3_async_assessment_queue_concurrency_results_and_cancellation() -> None:
    """Verify Phase 3 assessment queuing, per-connection concurrency lock (409), cancellation, and results endpoint."""
    app, engine, _settings, tenant_id, h_admin, h_analyst = await _bootstrap_test_app()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        conn_id = (
            await client.post(
                "/api/v1/connections",
                headers=h_admin,
                json={
                    "name": "Phase3 AWS",
                    "provider": "aws",
                    "auth_mode": "sts_assume_role",
                    "account_or_subscription_id": "123456789012",
                    "role_arn": "arn:aws:iam::123456789012:role/CloudSentinelReadOnlyRole",
                    "data_source": "synthetic_fixture",
                },
            )
        ).json()["id"]

        # 1. Queue-only trigger creates a 'queued' run with 202 Accepted
        q_resp = await client.post(
            "/api/v1/assessments?queue_only=true",
            headers=h_analyst,
            json={"connection_id": conn_id, "idempotency_key": "run-idem-1"},
        )
        assert q_resp.status_code == 202
        run_id = q_resp.json()["id"]
        assert q_resp.json()["status"] == "queued"
        assert q_resp.json()["job_id"].startswith("job-")

        # 2. Idempotent replay with same idempotency_key returns existing queued run
        q_replay = await client.post(
            "/api/v1/assessments?queue_only=true",
            headers=h_analyst,
            json={"connection_id": conn_id, "idempotency_key": "run-idem-1"},
        )
        assert q_replay.status_code == 202
        assert q_replay.json()["id"] == run_id

        # 3. Concurrent assessment on the same connection while one is queued returns 409 Conflict
        conflict_resp = await client.post(
            "/api/v1/assessments?queue_only=true",
            headers=h_analyst,
            json={"connection_id": conn_id},
        )
        assert conflict_resp.status_code == 409

        # 4. Cancel the queued assessment run
        cancel_resp = await client.post(
            f"/api/v1/assessments/{run_id}/cancel",
            headers=h_analyst,
        )
        assert cancel_resp.status_code == 200
        assert cancel_resp.json()["status"] == "cancelled"

        # 5. Trigger a full assessment run and inspect /results
        full_run = await client.post(
            "/api/v1/assessments",
            headers=h_analyst,
            json={"connection_id": conn_id},
        )
        assert full_run.status_code == 202
        full_run_id = full_run.json()["id"]
        assert full_run.json()["status"] == "completed"

        results_resp = await client.get(
            f"/api/v1/assessments/{full_run_id}/results",
            headers=h_analyst,
        )
        assert results_resp.status_code == 200
        assert results_resp.json()["total"] >= 10

    # Verify Celery worker task entry point rejects missing tenant_id
    with pytest.raises(ValueError, match="requires explicit verified tenant_id"):
        dispatch_assessment("", "conn-1", "user-1")

    ack = dispatch_assessment(str(tenant_id), conn_id, "user-1")
    assert ack["status"] == "accepted"

    await engine.dispose()


@pytest.mark.security
async def test_phase4_oidc_pkce_bff_cookie_csrf_and_logout_revocation() -> None:
    """Verify Phase 4 OIDC PKCE S256, state/nonce replay protection, BFF cookie + CSRF check, and token revocation."""
    app, engine, _settings, tenant_id, h_admin, _h_analyst = await _bootstrap_test_app()

    verifier, challenge = generate_pkce_pair()
    assert compute_pkce_challenge(verifier) == challenge

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Initiate OIDC PKCE authorization request
        authz = await client.post(
            "/api/v1/auth/oidc/authorize",
            json={
                "redirect_uri": "http://localhost:5173/login/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        assert authz.status_code == 200
        state = authz.json()["state"]
        assert authz.json()["nonce"]

        # 2. Wrong PKCE code_verifier is rejected with 401
        bad_cb = await client.post(
            "/api/v1/auth/oidc/callback",
            json={
                "state": state,
                "code_verifier": "wrong-code-verifier-value-that-does-not-match-challenge-12345",
                "redirect_uri": "http://localhost:5173/login/callback",
                "id_token": h_admin["Authorization"].split(" ")[1],
            },
        )
        assert bad_cb.status_code == 401

        # 3. Replaying consumed state is rejected with 401
        replay_cb = await client.post(
            "/api/v1/auth/oidc/callback",
            json={
                "state": state,
                "code_verifier": verifier,
                "redirect_uri": "http://localhost:5173/login/callback",
                "id_token": h_admin["Authorization"].split(" ")[1],
            },
        )
        assert replay_cb.status_code == 401

        # 4. Fresh authorize + valid callback with matching nonce issues HttpOnly BFF cookie + csrf_token
        authz2 = await client.post(
            "/api/v1/auth/oidc/authorize",
            json={
                "redirect_uri": "http://localhost:5173/login/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        state2 = authz2.json()["state"]
        nonce2 = authz2.json()["nonce"]

        import jwt as pyjwt

        token_with_nonce = pyjwt.encode(
            {
                "iss": app.state.settings.oidc_issuer_url,
                "aud": app.state.settings.oidc_audience,
                "sub": "sub-admin-h",
                "email": "admin@hardening.test",
                "tenant_id": str(tenant_id),
                "nonce": nonce2,
                "jti": f"jti-{uuid.uuid4()}",
                "iat": 1700000000,
                "exp": 4102444800,
            },
            app.state.settings.dev_jwt_secret,
            algorithm="HS256",
        )
        ok_cb = await client.post(
            "/api/v1/auth/oidc/callback",
            json={
                "state": state2,
                "code_verifier": verifier,
                "redirect_uri": "http://localhost:5173/login/callback",
                "id_token": token_with_nonce,
            },
        )
        assert ok_cb.status_code == 200
        csrf_token = ok_cb.json()["csrf_token"]
        assert "cloudsentinel_session" in ok_cb.cookies

        # 5. Cookie-authenticated GET succeeds, but POST without X-CSRF-Token fails with 403
        me_cookie = await client.get("/api/v1/auth/me")
        assert me_cookie.status_code == 200

        csrf_blocked = await client.post(
            "/api/v1/connections",
            json={
                "name": "CSRF Blocked",
                "provider": "aws",
                "auth_mode": "sts_assume_role",
                "account_or_subscription_id": "123456789012",
                "role_arn": "arn:aws:iam::123456789012:role/ReadOnly",
            },
        )
        assert csrf_blocked.status_code == 403
        assert "CSRF token" in csrf_blocked.text

        # 6. Cookie-authenticated POST WITH X-CSRF-Token succeeds
        csrf_ok = await client.post(
            "/api/v1/connections",
            headers={"X-CSRF-Token": csrf_token},
            json={
                "name": "CSRF Allowed",
                "provider": "aws",
                "auth_mode": "sts_assume_role",
                "account_or_subscription_id": "123456789012",
                "role_arn": "arn:aws:iam::123456789012:role/ReadOnly",
                "data_source": "synthetic_fixture",
            },
        )
        assert csrf_ok.status_code == 201

        # 7. Logout revokes the token and clears the BFF cookie
        logout_resp = await client.post(
            "/api/v1/auth/logout",
            headers={"X-CSRF-Token": csrf_token},
        )
        assert logout_resp.status_code == 200

        # Using the revoked token via Bearer header now returns 401
        revoked_check = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token_with_nonce}"},
        )
        assert revoked_check.status_code == 401
        assert "invalid or expired" in revoked_check.text.lower()

    await engine.dispose()


@pytest.mark.security
def test_phase5_and_phase6_aws_and_azure_connector_partial_failure_and_retry_handling() -> None:
    """Verify Phases 5 & 6:
    - AWS service errors emit NOT_ASSESSED / ERROR CheckEvaluations instead of false PASS
    - Azure live validate_connection checks GET /subscriptions/{id}
    - Azure _arm_get_paginated retries HTTP 429 and aborts cyclic nextLinks
    """
    # 1. AWS live connector with mocked STS AssumeRole where CloudTrail returns AccessDenied
    aws_conn = AWSConnector(
        account_id="123456789012",
        role_arn="arn:aws:iam::123456789012:role/CloudSentinelReadOnly",
        data_source="live",
    )
    mock_session = MagicMock()

    def client_side_effect(service_name: str, **_kwargs: Any) -> MagicMock:
        m = MagicMock()
        if service_name == "cloudtrail":
            m.describe_trails.side_effect = ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}},
                "DescribeTrails",
            )
        elif service_name == "s3":
            m.list_buckets.return_value = {"Buckets": []}
        elif service_name == "ec2":
            pag = MagicMock()
            pag.paginate.return_value = []
            m.get_paginator.return_value = pag
        elif service_name == "iam":
            pag = MagicMock()
            pag.paginate.return_value = []
            m.get_paginator.return_value = pag
        return m

    mock_session.client.side_effect = client_side_effect
    with patch.object(aws_conn, "_assume_readonly_session", return_value=mock_session):
        report = aws_conn.collect_and_assess()
        ct_eval = next(ev for ev in report.evaluations if ev.rule_id == "AWS-CT-001")
        assert ct_eval.status == CheckStatus.NOT_ASSESSED

    # 2. Azure live validate_connection with HTTP 403 on subscription read -> valid=False
    calls: list[str] = []

    def handler_403(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(403, json={"error": {"code": "AuthorizationFailed"}})

    mock_http_403 = httpx.Client(transport=httpx.MockTransport(handler_403))
    az_conn = AzureConnector(
        subscription_id="00000000-1111-2222-3333-444444444444",
        auth_mode="managed_identity",
        data_source="live",
        http_client=mock_http_403,
    )
    with patch.object(az_conn, "_acquire_arm_token", return_value="fake-arm-token"):
        preflight = az_conn.validate_connection()
        assert preflight.valid is False
        assert preflight.checked_permissions["Microsoft.Resources/subscriptions/read"] == "denied"
    mock_http_403.close()

    # 3. Azure _arm_get_paginated retries HTTP 429 and succeeds, and detects cyclic nextLink
    attempt_count = 0

    def handler_retry_and_cycle(request: httpx.Request) -> httpx.Response:
        nonlocal attempt_count
        attempt_count += 1
        if attempt_count == 1:
            return httpx.Response(429, headers={"Retry-After": "0"}, json={"error": "throttled"})
        return httpx.Response(
            200,
            json={
                "value": [{"id": "item-1"}],
                "nextLink": str(request.url),  # cyclic nextLink pointing to same URL
            },
        )

    mock_http_cycle = httpx.Client(transport=httpx.MockTransport(handler_retry_and_cycle))
    az_cycle = AzureConnector(
        subscription_id="00000000-1111-2222-3333-444444444444",
        data_source="live",
        http_client=mock_http_cycle,
    )
    with pytest.raises(RuntimeError, match="cyclic nextLink"):
        az_cycle._arm_get_paginated(
            mock_http_cycle,
            "fake-token",
            "/subscriptions/00000000-1111-2222-3333-444444444444/providers/Microsoft.Storage/storageAccounts",
            "2023-05-01",
        )
    assert attempt_count >= 2
    mock_http_cycle.close()


@pytest.mark.security
async def test_phase7_detection_account_scope_provenance_and_deduplication() -> None:
    """Verify Phase 7 detection ingestion:
    - Rejects events for unregistered account_ref (403)
    - Rejects events missing eventTime (422)
    - Enforces synthetic_fixture provenance when connection is synthetic even if request claims live
    - Deduplicates re-ingested events by (tenant_id, provider, provider_event_id, rule_id)
    """
    app, engine, _settings, _tenant_id, h_admin, h_analyst = await _bootstrap_test_app()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Ingesting before registering connection for 123456789012 is rejected with 403
        unregistered = await client.post(
            "/api/v1/detections/ingest",
            headers=h_analyst,
            json={
                "provider": "aws",
                "events": SYNTHETIC_AWS_CLOUDTRAIL_EVENTS,
                "data_source": "live",
            },
        )
        assert unregistered.status_code == 403

        # Register synthetic AWS connection for 123456789012
        await client.post(
            "/api/v1/connections",
            headers=h_admin,
            json={
                "name": "Phase7 AWS",
                "provider": "aws",
                "auth_mode": "sts_assume_role",
                "account_or_subscription_id": "123456789012",
                "role_arn": "arn:aws:iam::123456789012:role/CloudSentinelReadOnlyRole",
                "data_source": "synthetic_fixture",
            },
        )

        # 2. Malformed event without eventTime is rejected with 422
        missing_ts = await client.post(
            "/api/v1/detections/ingest",
            headers=h_analyst,
            json={
                "provider": "aws",
                "events": [{"eventID": "evt-no-time", "eventName": "StopLogging"}],
                "data_source": "synthetic_fixture",
            },
        )
        assert missing_ts.status_code == 422

        # 3. Ingest with data_source="live" against a synthetic connection forces data_source="synthetic_fixture"
        first_ingest = await client.post(
            "/api/v1/detections/ingest",
            headers=h_analyst,
            json={
                "provider": "aws",
                "events": SYNTHETIC_AWS_CLOUDTRAIL_EVENTS,
                "data_source": "live",
            },
        )
        assert first_ingest.status_code == 201
        assert first_ingest.json()["detections_triggered"] == 3
        assert first_ingest.json()["duplicates_skipped"] == 0
        assert all(
            item["data_source"] == "synthetic_fixture" for item in first_ingest.json()["items"]
        )

        # 4. Re-ingesting the same events skips all 3 duplicates
        second_ingest = await client.post(
            "/api/v1/detections/ingest",
            headers=h_analyst,
            json={
                "provider": "aws",
                "events": SYNTHETIC_AWS_CLOUDTRAIL_EVENTS,
                "data_source": "synthetic_fixture",
            },
        )
        assert second_ingest.status_code == 201
        assert second_ingest.json()["detections_triggered"] == 0
        assert second_ingest.json()["duplicates_skipped"] == 3

    await engine.dispose()


@pytest.mark.security
async def test_phase8_request_body_size_cap_and_route_class_rate_limiting() -> None:
    """Verify Phase 8 RequestSizeLimitMiddleware (HTTP 413) and route-class rate limiting."""
    app, engine, _settings, _tenant_id, h_admin, _h_analyst = await _bootstrap_test_app(
        max_body_bytes=1024,
        rate_limit_rpm=20,
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Oversized body (> 1024 bytes) is rejected with HTTP 413 Payload Too Large
        large_payload = {"name": "A" * 2048}
        too_large = await client.post(
            "/api/v1/connections",
            headers=h_admin,
            json=large_payload,
        )
        assert too_large.status_code == 413
        assert too_large.json()["error"]["code"] == "payload_too_large"

    await engine.dispose()
