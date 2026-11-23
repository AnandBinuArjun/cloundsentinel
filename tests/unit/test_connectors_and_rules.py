"""Unit tests for AWS/Azure connectors, rules, risk engine, detections, compliance, and SSRF."""

from __future__ import annotations

import pytest

from cloud_connectors.aws.connector import AWSConnector
from cloud_connectors.aws.rules import evaluate_aws_s3_bucket, evaluate_aws_security_monitoring
from cloud_connectors.azure.connector import AzureConnector
from compliance.loader import compute_compliance_posture
from detections.engine import (
    evaluate_events,
    normalize_aws_cloudtrail_event,
    normalize_azure_activity_event,
)
from detections.fixtures import (
    SYNTHETIC_AWS_CLOUDTRAIL_EVENTS,
    SYNTHETIC_AZURE_ACTIVITY_EVENTS,
)
from packages.assessment.interface import CheckStatus
from packages.assessment.risk import calculate_risk_score
from packages.common.ssrf import validate_outbound_https_url


@pytest.mark.unit
def test_aws_connector_rejects_root_arn_and_validates_fixture() -> None:
    root_conn = AWSConnector(
        account_id="123456789012",
        role_arn="arn:aws:iam::123456789012:root",
        data_source="synthetic_fixture",
    )
    res_bad = root_conn.validate_connection()
    assert res_bad.valid is False
    assert any("root" in err.lower() for err in res_bad.errors)

    good_conn = AWSConnector(
        account_id="123456789012",
        role_arn="arn:aws:iam::123456789012:role/CloudSentinelReadOnlyRole",
        external_id="ext-123",
        data_source="synthetic_fixture",
    )
    res_good = good_conn.validate_connection()
    assert res_good.valid is True
    assert res_good.data_source == "synthetic_fixture"

    report = good_conn.collect_and_assess()
    assert len(report.assets) >= 8
    statuses = {ev.status for ev in report.evaluations}
    assert CheckStatus.PASS in statuses
    assert CheckStatus.FAIL in statuses

    id_report = good_conn.analyze_identities()
    assert len(id_report.findings) >= 2
    assert len(id_report.limitations) >= 1


@pytest.mark.unit
def test_aws_api_error_never_coerced_to_pass() -> None:
    s3_evals = evaluate_aws_s3_bucket(
        account_id="123456789012",
        bucket={
            "name": "denied-bucket",
            "region": "us-east-1",
            "public_access_block": {"error": "AccessDenied"},
            "encryption": {"error": "AccessDenied"},
        },
        data_source="live",
    )
    assert s3_evals[0].status == CheckStatus.ERROR
    assert s3_evals[1].status == CheckStatus.ERROR

    mon_eval = evaluate_aws_security_monitoring(
        account_id="123456789012",
        monitoring={"permission_denied": True},
        data_source="live",
    )
    assert mon_eval.status == CheckStatus.NOT_ASSESSED


@pytest.mark.unit
def test_azure_connector_validation_rules_and_identity_limitations() -> None:
    bad_conn = AzureConnector(subscription_id="not-a-uuid", data_source="synthetic_fixture")
    assert bad_conn.validate_connection().valid is False

    good_conn = AzureConnector(
        subscription_id="00000000-1111-2222-3333-444444444444",
        auth_mode="managed_identity",
        data_source="synthetic_fixture",
    )
    assert good_conn.validate_connection().valid is True
    report = good_conn.collect_and_assess()
    assert len(report.assets) >= 5
    rule_ids = {ev.rule_id for ev in report.evaluations}
    assert {
        "AZ-STG-001",
        "AZ-STG-002",
        "AZ-STG-003",
        "AZ-NET-001",
        "AZ-IAM-001",
        "AZ-KV-001",
        "AZ-MON-001",
        "AZ-MON-002",
    }.issubset(rule_ids)

    id_report = good_conn.analyze_identities()
    assert len(id_report.findings) >= 2
    assert any("Graph" in lim for lim in id_report.limitations)


@pytest.mark.unit
def test_transparent_risk_engine_ranks_exposed_critical_above_internal_low() -> None:
    high_risk = calculate_risk_score(
        severity="critical",
        internet_exposed=True,
        asset_criticality="high",
        identity_privilege="admin",
        confidence="high",
    )
    low_risk = calculate_risk_score(
        severity="low",
        internet_exposed=False,
        asset_criticality="low",
        identity_privilege="none",
        confidence="medium",
    )
    assert high_risk.score > low_risk.score
    assert high_risk.priority_tier.startswith("P0")
    assert "not an externally validated" in high_risk.explanation["disclaimer"]


@pytest.mark.unit
def test_threat_detection_engine_correlates_actor_events_and_maps_mitre() -> None:
    aws_events = [
        normalize_aws_cloudtrail_event(e, "synthetic_fixture")
        for e in SYNTHETIC_AWS_CLOUDTRAIL_EVENTS
    ]
    az_events = [
        normalize_azure_activity_event(e, "synthetic_fixture")
        for e in SYNTHETIC_AZURE_ACTIVITY_EVENTS
    ]

    detections = evaluate_events(aws_events + az_events)
    rule_ids = {d.rule.rule_id for d in detections}
    assert {"DET-AWS-001", "DET-AWS-003", "DET-AWS-004", "DET-AZ-001", "DET-AZ-003"}.issubset(
        rule_ids
    )
    # All 3 AWS events come from same actor within 8 minutes -> correlated
    aws_stop_logging = next(d for d in detections if d.rule.rule_id == "DET-AWS-001")
    assert aws_stop_logging.rule.mitre_technique == "T1562.008"
    assert len(aws_stop_logging.correlated_event_ids) == 2


@pytest.mark.unit
def test_compliance_posture_never_marks_unassessed_or_error_as_pass() -> None:
    posture = compute_compliance_posture(
        {
            "AWS-S3-001": ["PASS"],
            "AWS-S3-003": ["PASS"],
            "AWS-IAM-001": ["FAIL"],
            "AWS-EBS-001": ["ERROR"],
        }
    )
    assert "NEVER establishes full organizational compliance" in posture["disclaimer"]
    cis_aws = next(fw for fw in posture["frameworks"] if fw["id"] == "cis-aws-3.0")
    ctrls = {c["control_id"]: c["status"] for c in cis_aws["controls"]}
    assert ctrls["CIS-AWS-2.1.4"] == "PASS"
    assert ctrls["CIS-AWS-1.16"] == "FAIL"
    assert ctrls["CIS-AWS-2.2.1"] == "ERROR"
    assert ctrls["CIS-AWS-3.1"] == "NOT_ASSESSED"


@pytest.mark.unit
def test_ssrf_validator_blocks_metadata_and_private_targets() -> None:
    assert (
        validate_outbound_https_url("https://sts.us-east-1.amazonaws.com")
        == "https://sts.us-east-1.amazonaws.com"
    )
    for bad in (
        "http://example.com",
        "https://169.254.169.254/latest/meta-data/",
        "https://127.0.0.1:8000/health",
        "https://10.0.0.5/internal",
        "https://metadata.azure.com/metadata",
        "https://service.internal/api",
    ):
        with pytest.raises(ValueError):
            validate_outbound_https_url(bad)
