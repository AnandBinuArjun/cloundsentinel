"""Assessment orchestration service uniting AWS/Azure connectors, findings, and evidence."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.services.audit import record_audit_event
from cloud_connectors.aws.connector import AWSConnector
from cloud_connectors.azure.connector import AzureConnector
from packages.assessment.interface import (
    CheckStatus,
    CloudProviderConnector,
    PreflightResult,
)
from packages.assessment.risk import calculate_risk_score
from packages.auth.rbac import AuthContext, Permission
from packages.common.redaction import redact_data
from packages.db.models import (
    AssessmentResult,
    AssessmentRun,
    Asset,
    CloudAccount,
    CloudConnection,
    Evidence,
    Finding,
    FindingHistory,
    SecurityRule,
)


def build_connector(connection: CloudConnection) -> CloudProviderConnector:
    """Instantiate the appropriate read-only cloud connector for a CloudConnection."""
    if connection.provider == "aws":
        return AWSConnector(
            account_id=connection.account_or_subscription_id,
            role_arn=connection.role_arn,
            external_id=connection.external_id,
            regions=list(connection.regions or ["us-east-1"]),
            data_source=connection.data_source,
        )
    if connection.provider == "azure":
        return AzureConnector(
            subscription_id=connection.account_or_subscription_id,
            azure_tenant_id=connection.azure_tenant_id,
            auth_mode=connection.auth_mode,
            azure_client_id=connection.azure_client_id,
            data_source=connection.data_source,
        )
    raise ValueError(f"Unsupported cloud provider: {connection.provider}")


async def validate_cloud_connection(
    session: AsyncSession,
    *,
    auth: AuthContext,
    connection: CloudConnection,
) -> PreflightResult:
    """Execute read-only identity & permission preflight and update connection status."""
    auth.require_permission(Permission.CONNECTIONS_WRITE)
    if connection.tenant_id != auth.tenant_id:
        raise PermissionError("Cross-tenant connection validation denied.")

    connector = build_connector(connection)
    preflight = connector.validate_connection()

    connection.status = "healthy" if preflight.valid else "error"
    connection.last_validated_at = preflight.validated_at
    connection.preflight_summary = {
        "valid": preflight.valid,
        "identity": preflight.identity_arn_or_principal,
        "checked_permissions": preflight.checked_permissions,
        "errors": preflight.errors,
        "data_source": preflight.data_source,
    }

    if preflight.valid:
        acct_stmt = select(CloudAccount).where(
            CloudAccount.tenant_id == auth.tenant_id,
            CloudAccount.provider == connection.provider,
            CloudAccount.external_account_id == preflight.account_or_subscription_id,
        )
        existing_acct = (await session.execute(acct_stmt)).scalar_one_or_none()
        if existing_acct is None:
            session.add(
                CloudAccount(
                    tenant_id=auth.tenant_id,
                    connection_id=connection.id,
                    provider=connection.provider,
                    external_account_id=preflight.account_or_subscription_id,
                    display_name=connection.name,
                    status="active",
                    metadata_json={
                        "auth_mode": connection.auth_mode,
                        "data_source": connection.data_source,
                    },
                )
            )

    await record_audit_event(
        session,
        auth=auth,
        action="connection.validated",
        resource_type="cloud_connection",
        resource_id=str(connection.id),
        details={
            "provider": connection.provider,
            "valid": preflight.valid,
            "errors": preflight.errors,
        },
    )
    await session.commit()
    return preflight


async def execute_assessment_run(
    session: AsyncSession,
    *,
    auth: AuthContext,
    connection: CloudConnection,
) -> AssessmentRun:
    """Run asset discovery + deterministic checks and persist normalized findings and evidence."""
    auth.require_permission(Permission.ASSESSMENTS_RUN)
    if connection.tenant_id != auth.tenant_id:
        raise PermissionError("Cross-tenant assessment execution denied.")

    run = AssessmentRun(
        tenant_id=auth.tenant_id,
        connection_id=connection.id,
        provider=connection.provider,
        status="running",
        data_source=connection.data_source,
        triggered_by=auth.user_id,
    )
    session.add(run)
    await session.flush()

    connector = build_connector(connection)
    report = connector.collect_and_assess()

    # Upsert discovered assets
    asset_id_by_resource: dict[str, uuid.UUID] = {}
    now = datetime.now(UTC)
    for item in report.assets:
        stmt = select(Asset).where(
            Asset.tenant_id == auth.tenant_id,
            Asset.provider == item.provider,
            Asset.account_ref == item.account_ref,
            Asset.resource_id == item.resource_id,
        )
        existing = (await session.execute(stmt)).scalar_one_or_none()
        if existing is None:
            asset = Asset(
                tenant_id=auth.tenant_id,
                connection_id=connection.id,
                provider=item.provider,
                account_ref=item.account_ref,
                resource_id=item.resource_id,
                resource_name=item.resource_name,
                resource_type=item.resource_type,
                region=item.region,
                tags=redact_data(item.tags),
                configuration=redact_data(item.configuration),
                collection_status=item.collection_status,
                data_source=item.data_source,
                discovered_at=now,
                last_observed_at=now,
            )
            session.add(asset)
            await session.flush()
            asset_id_by_resource[item.resource_id] = asset.id
        else:
            existing.resource_name = item.resource_name
            existing.tags = redact_data(item.tags)
            existing.configuration = redact_data(item.configuration)
            existing.collection_status = item.collection_status
            existing.last_observed_at = now
            asset_id_by_resource[item.resource_id] = existing.id

    passed = failed = not_assessed = errored = 0
    for ev in report.evaluations:
        # Ensure SecurityRule catalog entry exists
        existing_rule = await session.get(SecurityRule, ev.rule_id)
        if existing_rule is None:
            session.add(
                SecurityRule(
                    id=ev.rule_id,
                    provider=ev.provider,
                    title=ev.title,
                    description=ev.description,
                    severity=ev.severity.value,
                    confidence=ev.confidence.value,
                    required_permissions=ev.required_permissions,
                    expected_configuration=str(ev.expected_config),
                    remediation_guidance=ev.remediation_guidance,
                    framework_mappings=ev.framework_mappings,
                    version=ev.rule_version,
                )
            )
            await session.flush()

        asset_uuid = asset_id_by_resource.get(ev.resource_id)
        result_row = AssessmentResult(
            tenant_id=auth.tenant_id,
            assessment_run_id=run.id,
            asset_id=asset_uuid,
            rule_id=ev.rule_id,
            rule_version=ev.rule_version,
            provider=ev.provider,
            account_ref=ev.account_ref,
            resource_id=ev.resource_id,
            region=ev.region,
            status=ev.status.value,
            severity=ev.severity.value,
            confidence=ev.confidence.value,
            expected_config=redact_data(ev.expected_config),
            observed_config=redact_data(ev.observed_config),
            explanation=ev.explanation,
            evaluated_at=now,
        )
        session.add(result_row)
        await session.flush()

        if ev.status == CheckStatus.PASS:
            passed += 1
        elif ev.status == CheckStatus.FAIL:
            failed += 1
        elif ev.status == CheckStatus.NOT_ASSESSED:
            not_assessed += 1
        else:
            errored += 1

        # Deduplicate & upsert active Finding on FAIL, or auto-resolve open Finding on PASS
        find_stmt = select(Finding).where(
            Finding.tenant_id == auth.tenant_id,
            Finding.rule_id == ev.rule_id,
            Finding.resource_id == ev.resource_id,
        )
        existing_finding = (await session.execute(find_stmt)).scalar_one_or_none()

        if ev.status == CheckStatus.FAIL:
            risk = calculate_risk_score(
                severity=ev.severity.value,
                internet_exposed=ev.internet_exposed,
                asset_criticality=ev.asset_criticality,
                identity_privilege=ev.identity_privilege,
                confidence=ev.confidence.value,
            )
            if existing_finding is None:
                finding = Finding(
                    tenant_id=auth.tenant_id,
                    asset_id=asset_uuid,
                    latest_result_id=result_row.id,
                    rule_id=ev.rule_id,
                    rule_version=ev.rule_version,
                    provider=ev.provider,
                    account_ref=ev.account_ref,
                    resource_id=ev.resource_id,
                    resource_type=ev.resource_type,
                    region=ev.region,
                    title=ev.title,
                    description=ev.description,
                    severity=ev.severity.value,
                    confidence=ev.confidence.value,
                    status="open",
                    risk_score=risk.score,
                    risk_explanation=risk.explanation,
                    remediation_guidance=ev.remediation_guidance,
                    framework_mappings=ev.framework_mappings,
                    limitations=ev.limitations,
                    data_source=ev.data_source,
                    first_seen_at=now,
                    last_seen_at=now,
                )
                session.add(finding)
                await session.flush()
            else:
                finding = existing_finding
                finding.latest_result_id = result_row.id
                finding.risk_score = risk.score
                finding.risk_explanation = risk.explanation
                finding.last_seen_at = now
                if finding.status == "resolved":
                    finding.status = "open"
                    session.add(
                        FindingHistory(
                            tenant_id=auth.tenant_id,
                            finding_id=finding.id,
                            actor_user_id=auth.user_id,
                            previous_status="resolved",
                            new_status="open",
                            justification="Re-opened by assessment run after check failed again.",
                        )
                    )

            session.add(
                Evidence(
                    tenant_id=auth.tenant_id,
                    finding_id=finding.id,
                    source=f"{ev.provider}:{ev.rule_id}@{ev.rule_version}",
                    expected_config=redact_data(ev.expected_config),
                    observed_config=redact_data(ev.observed_config),
                    raw_evidence_redacted=redact_data(ev.evidence),
                    collected_at=now,
                )
            )
        elif (
            ev.status == CheckStatus.PASS
            and existing_finding is not None
            and existing_finding.status == "open"
        ):
            existing_finding.status = "resolved"
            existing_finding.latest_result_id = result_row.id
            existing_finding.last_seen_at = now
            session.add(
                FindingHistory(
                    tenant_id=auth.tenant_id,
                    finding_id=existing_finding.id,
                    actor_user_id=auth.user_id,
                    previous_status="open",
                    new_status="resolved",
                    justification="Verified PASS in subsequent assessment run.",
                )
            )

    run.assets_discovered = len(report.assets)
    run.checks_passed = passed
    run.checks_failed = failed
    run.checks_not_assessed = not_assessed
    run.checks_errored = errored
    run.partial_failures = report.partial_failures
    run.status = "completed_with_warnings" if report.partial_failures else "completed"
    run.completed_at = datetime.now(UTC)

    await record_audit_event(
        session,
        auth=auth,
        action="assessment.completed",
        resource_type="assessment_run",
        resource_id=str(run.id),
        details={
            "provider": run.provider,
            "data_source": run.data_source,
            "assets_discovered": run.assets_discovered,
            "checks_failed": run.checks_failed,
            "partial_failures": len(run.partial_failures),
        },
    )
    await session.commit()
    await session.refresh(run)
    return run
