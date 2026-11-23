"""Deterministic AWS security posture rules (10 core checks)."""

from __future__ import annotations

from typing import Any

from packages.assessment.interface import (
    CheckEvaluation,
    CheckStatus,
    Confidence,
    Severity,
)

RULE_VERSION = "1.0.0"


def evaluate_aws_s3_bucket(
    *,
    account_id: str,
    bucket: dict[str, Any],
    data_source: str,
) -> list[CheckEvaluation]:
    """Evaluate S3 public access, encryption, and bucket policy rules."""
    name = str(bucket.get("name", "unknown-bucket"))
    region = str(bucket.get("region", "us-east-1"))
    arn = f"arn:aws:s3:::{name}"
    results: list[CheckEvaluation] = []

    # AWS-S3-001: Public Access Block
    pab = bucket.get("public_access_block")
    if pab is None:
        status_001 = CheckStatus.FAIL
        explanation_001 = "No S3 Block Public Access configuration found on bucket."
        exposed = True
    elif pab.get("error"):
        status_001 = CheckStatus.ERROR
        explanation_001 = f"Failed to read Block Public Access: {pab['error']}"
        exposed = False
    else:
        all_blocked = all(
            bool(pab.get(flag, False))
            for flag in (
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            )
        )
        status_001 = CheckStatus.PASS if all_blocked else CheckStatus.FAIL
        exposed = not all_blocked
        explanation_001 = (
            "All four S3 Block Public Access flags are enabled."
            if all_blocked
            else "One or more S3 Block Public Access flags are disabled."
        )

    results.append(
        CheckEvaluation(
            rule_id="AWS-S3-001",
            rule_version=RULE_VERSION,
            provider="aws",
            account_ref=account_id,
            resource_id=arn,
            resource_type="aws_s3_bucket",
            region=region,
            title="S3 bucket must block public access",
            description="Ensures all four S3 Block Public Access settings are enabled.",
            status=status_001,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            required_permissions=["s3:GetBucketPublicAccessBlock"],
            expected_config={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
            observed_config=pab if isinstance(pab, dict) else {"configured": False},
            evidence={"bucket": name, "public_access_block": pab},
            explanation=explanation_001,
            remediation_guidance=(
                "Enable all four S3 Block Public Access flags via PutPublicAccessBlock "
                "and verify no public bucket ACLs remain."
            ),
            framework_mappings=["CIS-AWS-2.1.4", "NIST-CSF-PR.DS-01", "ISO27001-A.8.24"],
            internet_exposed=exposed,
            asset_criticality="high",
            data_source=data_source,
        )
    )

    # AWS-S3-002: Server-Side Encryption
    enc = bucket.get("encryption")
    if isinstance(enc, dict) and enc.get("error"):
        status_002 = CheckStatus.ERROR
        explanation_002 = f"Failed to read bucket encryption: {enc['error']}"
    elif isinstance(enc, dict) and enc.get("enabled") is True:
        status_002 = CheckStatus.PASS
        explanation_002 = f"Bucket default encryption enabled ({enc.get('algorithm', 'AES256')})."
    else:
        status_002 = CheckStatus.FAIL
        explanation_002 = "Bucket default server-side encryption is disabled or missing."

    results.append(
        CheckEvaluation(
            rule_id="AWS-S3-002",
            rule_version=RULE_VERSION,
            provider="aws",
            account_ref=account_id,
            resource_id=arn,
            resource_type="aws_s3_bucket",
            region=region,
            title="S3 bucket must enforce server-side encryption",
            description="Ensures default SSE-S3 or SSE-KMS encryption is enabled on S3 buckets.",
            status=status_002,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            required_permissions=["s3:GetEncryptionConfiguration"],
            expected_config={"enabled": True, "algorithm": "AES256 or aws:kms"},
            observed_config=enc if isinstance(enc, dict) else {"enabled": False},
            evidence={"bucket": name, "encryption": enc},
            explanation=explanation_002,
            remediation_guidance="Configure default SSE-KMS (preferred) or SSE-S3 encryption.",
            framework_mappings=["CIS-AWS-2.1.1", "NIST-CSF-PR.DS-01", "ISO27001-A.8.24"],
            asset_criticality="high",
            data_source=data_source,
        )
    )

    # AWS-S3-003: Insecure Bucket Policy (Principal "*" Allow or missing Deny SecureTransport)
    policy = bucket.get("policy") or {}
    statements = policy.get("Statement", []) if isinstance(policy, dict) else []
    insecure_statements = [
        stmt
        for stmt in statements
        if isinstance(stmt, dict)
        and stmt.get("Effect") == "Allow"
        and (stmt.get("Principal") == "*" or stmt.get("Principal") == {"AWS": "*"})
        and not stmt.get("Condition")
    ]
    status_003 = CheckStatus.FAIL if insecure_statements else CheckStatus.PASS
    results.append(
        CheckEvaluation(
            rule_id="AWS-S3-003",
            rule_version=RULE_VERSION,
            provider="aws",
            account_ref=account_id,
            resource_id=arn,
            resource_type="aws_s3_bucket",
            region=region,
            title="S3 bucket policy must not grant unconditional wildcard principal access",
            description="Detects S3 bucket policies with Effect=Allow and Principal=* without conditions.",
            status=status_003,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            required_permissions=["s3:GetBucketPolicy"],
            expected_config={"unconditional_wildcard_allow_statements": 0},
            observed_config={"unconditional_wildcard_allow_statements": len(insecure_statements)},
            evidence={"bucket": name, "flagged_statements": insecure_statements},
            explanation=(
                f"Found {len(insecure_statements)} unconditional Principal='*' Allow statement(s)."
                if insecure_statements
                else "No unconditional wildcard Principal Allow statements detected."
            ),
            remediation_guidance="Scope S3 bucket policy Principal to explicit IAM ARNs and require aws:SecureTransport.",
            framework_mappings=["CIS-AWS-2.1.2", "NIST-CSF-PR.AA-05", "ISO27001-A.8.3"],
            internet_exposed=bool(insecure_statements),
            asset_criticality="high",
            data_source=data_source,
        )
    )
    return results


def evaluate_aws_security_group(
    *,
    account_id: str,
    sg: dict[str, Any],
    data_source: str,
) -> list[CheckEvaluation]:
    """Evaluate unrestricted inbound SSH (22) and RDP (3389) rules."""
    sg_id = str(sg.get("group_id", "sg-unknown"))
    region = str(sg.get("region", "us-east-1"))
    arn = f"arn:aws:ec2:{region}:{account_id}:security-group/{sg_id}"
    ingress = sg.get("ingress_rules", [])
    results: list[CheckEvaluation] = []

    for rule_id, port, proto_name, cis_id in (
        ("AWS-EC2-001", 22, "SSH", "CIS-AWS-5.2"),
        ("AWS-EC2-002", 3389, "RDP", "CIS-AWS-5.3"),
    ):
        offending: list[dict[str, Any]] = []
        for rule in ingress:
            from_p = int(rule.get("from_port", -1))
            to_p = int(rule.get("to_port", -1))
            cidrs = list(rule.get("cidrs", []))
            public_cidr = any(c in ("0.0.0.0/0", "::/0") for c in cidrs)
            covers_port = (from_p == -1 and to_p == -1) or (from_p <= port <= to_p)
            if public_cidr and covers_port:
                offending.append(rule)

        status = CheckStatus.FAIL if offending else CheckStatus.PASS
        results.append(
            CheckEvaluation(
                rule_id=rule_id,
                rule_version=RULE_VERSION,
                provider="aws",
                account_ref=account_id,
                resource_id=arn,
                resource_type="aws_security_group",
                region=region,
                title=f"Security group must not allow unrestricted inbound {proto_name} (port {port})",
                description=f"Checks that port {port} ({proto_name}) is not open to 0.0.0.0/0 or ::/0.",
                status=status,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                required_permissions=["ec2:DescribeSecurityGroups"],
                expected_config={"public_ingress_ports": []},
                observed_config={"offending_rules": offending},
                evidence={
                    "group_id": sg_id,
                    "group_name": sg.get("group_name"),
                    "offending_rules": offending,
                },
                explanation=(
                    f"Security group {sg_id} exposes port {port} ({proto_name}) to the public internet."
                    if offending
                    else f"Security group {sg_id} does not expose port {port} publicly."
                ),
                remediation_guidance=(
                    f"Restrict inbound port {port} to corporate bastion/VPN CIDRs or replace with AWS SSM Session Manager."
                ),
                framework_mappings=[cis_id, "NIST-CSF-PR.IR-01", "ISO27001-A.8.20"],
                internet_exposed=bool(offending),
                asset_criticality="high" if offending else "standard",
                data_source=data_source,
            )
        )
    return results


def evaluate_aws_ebs_volume(
    *,
    account_id: str,
    volume: dict[str, Any],
    data_source: str,
) -> CheckEvaluation:
    """Evaluate AWS-EBS-001: EBS volume encryption at rest."""
    vol_id = str(volume.get("volume_id", "vol-unknown"))
    region = str(volume.get("region", "us-east-1"))
    encrypted = bool(volume.get("encrypted", False))
    return CheckEvaluation(
        rule_id="AWS-EBS-001",
        rule_version=RULE_VERSION,
        provider="aws",
        account_ref=account_id,
        resource_id=f"arn:aws:ec2:{region}:{account_id}:volume/{vol_id}",
        resource_type="aws_ebs_volume",
        region=region,
        title="EBS volume must be encrypted at rest",
        description="Checks whether EBS volumes are encrypted using KMS.",
        status=CheckStatus.PASS if encrypted else CheckStatus.FAIL,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        required_permissions=["ec2:DescribeVolumes"],
        expected_config={"encrypted": True},
        observed_config={"encrypted": encrypted},
        evidence={"volume_id": vol_id, "encrypted": encrypted, "size_gb": volume.get("size_gb")},
        explanation=(
            f"EBS volume {vol_id} is encrypted at rest."
            if encrypted
            else f"EBS volume {vol_id} is NOT encrypted at rest."
        ),
        remediation_guidance=(
            "Enable EBS encryption by default per region and migrate unencrypted volumes via encrypted snapshots."
        ),
        framework_mappings=["CIS-AWS-2.2.1", "NIST-CSF-PR.DS-01", "ISO27001-A.8.24"],
        data_source=data_source,
    )


def evaluate_aws_cloudtrail(
    *,
    account_id: str,
    trails: list[dict[str, Any]],
    data_source: str,
) -> CheckEvaluation:
    """Evaluate AWS-CT-001: Multi-region CloudTrail logging active."""
    active_multi = [
        t for t in trails if t.get("is_multi_region") is True and t.get("is_logging") is True
    ]
    passed = bool(active_multi)
    return CheckEvaluation(
        rule_id="AWS-CT-001",
        rule_version=RULE_VERSION,
        provider="aws",
        account_ref=account_id,
        resource_id=f"arn:aws:cloudtrail:global:{account_id}:account-logging",
        resource_type="aws_cloudtrail",
        region="global",
        title="Multi-region CloudTrail logging must be enabled",
        description="Ensures at least one active multi-region CloudTrail trail records management events.",
        status=CheckStatus.PASS if passed else CheckStatus.FAIL,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        required_permissions=["cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus"],
        expected_config={"active_multi_region_trails": ">=1"},
        observed_config={
            "total_trails": len(trails),
            "active_multi_region_trails": len(active_multi),
        },
        evidence={"trails": trails},
        explanation=(
            f"Found {len(active_multi)} active multi-region CloudTrail trail(s)."
            if passed
            else "No active multi-region CloudTrail trail detected in account."
        ),
        remediation_guidance="Create and start a multi-region CloudTrail trail with log file validation enabled.",
        framework_mappings=["CIS-AWS-3.1", "NIST-CSF-DE.CM-01", "ISO27001-A.8.15"],
        asset_criticality="high",
        data_source=data_source,
    )


def evaluate_aws_iam_policy(
    *,
    account_id: str,
    policy: dict[str, Any],
    data_source: str,
) -> CheckEvaluation:
    """Evaluate AWS-IAM-001: Overly permissive wildcard IAM policies."""
    arn = str(policy.get("arn", f"arn:aws:iam::{account_id}:policy/unknown"))
    doc = policy.get("document") or {}
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    wildcard_stmts = []
    for stmt in statements:
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        actions_list = [actions] if isinstance(actions, str) else list(actions)
        resources_list = [resources] if isinstance(resources, str) else list(resources)
        if "*" in actions_list and "*" in resources_list:
            wildcard_stmts.append(stmt)

    failed = bool(wildcard_stmts)
    return CheckEvaluation(
        rule_id="AWS-IAM-001",
        rule_version=RULE_VERSION,
        provider="aws",
        account_ref=account_id,
        resource_id=arn,
        resource_type="aws_iam_policy",
        region="global",
        title="IAM policy must not grant full administrative wildcard (*:*) permissions",
        description="Detects customer-managed IAM policies allowing Action='*' on Resource='*'.",
        status=CheckStatus.FAIL if failed else CheckStatus.PASS,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        required_permissions=["iam:ListPolicies", "iam:GetPolicyVersion"],
        expected_config={"wildcard_admin_statements": 0},
        observed_config={"wildcard_admin_statements": len(wildcard_stmts)},
        evidence={"policy_arn": arn, "wildcard_statements": wildcard_stmts},
        explanation=(
            f"IAM policy {arn} contains {len(wildcard_stmts)} full wildcard administrative statement(s)."
            if failed
            else f"IAM policy {arn} does not contain full wildcard (*/*) Allow statements."
        ),
        remediation_guidance="Replace wildcard Action/Resource statements with least-privilege service-scoped actions.",
        framework_mappings=["CIS-AWS-1.16", "NIST-CSF-PR.AA-05", "ISO27001-A.8.2"],
        identity_privilege="admin" if failed else "standard",
        asset_criticality="high",
        limitations="Evaluates policy document syntax only; does not compute SCP or permission boundary intersections.",
        data_source=data_source,
    )


def evaluate_aws_iam_user(
    *,
    account_id: str,
    user: dict[str, Any],
    data_source: str,
) -> CheckEvaluation:
    """Evaluate AWS-IAM-002: Console user MFA and stale access key hygiene."""
    username = str(user.get("username", "unknown-user"))
    arn = str(user.get("arn", f"arn:aws:iam::{account_id}:user/{username}"))
    console_enabled = bool(user.get("console_access", False))
    mfa_enabled = bool(user.get("mfa_enabled", False))
    key_age_days = int(user.get("oldest_active_key_age_days", 0))

    issues: list[str] = []
    if console_enabled and not mfa_enabled:
        issues.append("Console access enabled without MFA device")
    if key_age_days > 90:
        issues.append(f"Active access key is {key_age_days} days old (>90 days)")

    failed = bool(issues)
    return CheckEvaluation(
        rule_id="AWS-IAM-002",
        rule_version=RULE_VERSION,
        provider="aws",
        account_ref=account_id,
        resource_id=arn,
        resource_type="aws_iam_user",
        region="global",
        title="IAM users must enforce MFA and rotate access keys within 90 days",
        description="Checks MFA enrollment for console IAM users and flags stale active access keys.",
        status=CheckStatus.FAIL if failed else CheckStatus.PASS,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        required_permissions=["iam:ListUsers", "iam:ListMFADevices", "iam:ListAccessKeys"],
        expected_config={"mfa_enabled_if_console": True, "max_key_age_days": 90},
        observed_config={
            "console_access": console_enabled,
            "mfa_enabled": mfa_enabled,
            "oldest_active_key_age_days": key_age_days,
        },
        evidence={"username": username, "issues": issues},
        explanation="; ".join(issues)
        if failed
        else f"IAM user {username} meets MFA and key-age baselines.",
        remediation_guidance="Enforce hardware/TOTP MFA, rotate keys >90 days, and migrate humans to AWS IAM Identity Center.",
        framework_mappings=["CIS-AWS-1.10", "CIS-AWS-1.14", "NIST-CSF-PR.AA-03", "ISO27001-A.8.5"],
        identity_privilege="admin" if user.get("has_admin_policy") else "standard",
        limitations="Key usage recency depends on IAM credential report availability.",
        data_source=data_source,
    )


def evaluate_aws_security_monitoring(
    *,
    account_id: str,
    monitoring: dict[str, Any],
    data_source: str,
) -> CheckEvaluation:
    """Evaluate AWS-MON-001: Security Hub / GuardDuty monitoring enabled."""
    if monitoring.get("permission_denied"):
        return CheckEvaluation(
            rule_id="AWS-MON-001",
            rule_version=RULE_VERSION,
            provider="aws",
            account_ref=account_id,
            resource_id=f"arn:aws:securityhub:global:{account_id}:monitoring",
            resource_type="aws_security_monitoring",
            region="global",
            title="AWS security monitoring (Security Hub / GuardDuty) should be enabled",
            description="Checks whether Security Hub or GuardDuty is active in the account.",
            status=CheckStatus.NOT_ASSESSED,
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            required_permissions=["securityhub:DescribeHub", "guardduty:ListDetectors"],
            expected_config={"security_hub_enabled": True, "guardduty_enabled": True},
            observed_config={"permission_denied": True},
            evidence=monitoring,
            explanation="Assessment role lacked Security Hub/GuardDuty read permissions; marked NOT_ASSESSED.",
            remediation_guidance="Grant securityhub:DescribeHub and guardduty:ListDetectors or enable both services.",
            framework_mappings=["NIST-CSF-DE.CM-09", "ISO27001-A.8.16"],
            data_source=data_source,
        )

    hub = bool(monitoring.get("security_hub_enabled", False))
    gd = bool(monitoring.get("guardduty_enabled", False))
    passed = hub and gd
    return CheckEvaluation(
        rule_id="AWS-MON-001",
        rule_version=RULE_VERSION,
        provider="aws",
        account_ref=account_id,
        resource_id=f"arn:aws:securityhub:global:{account_id}:monitoring",
        resource_type="aws_security_monitoring",
        region="global",
        title="AWS security monitoring (Security Hub / GuardDuty) must be enabled",
        description="Ensures AWS Security Hub and GuardDuty are enabled for threat and posture telemetry.",
        status=CheckStatus.PASS if passed else CheckStatus.FAIL,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        required_permissions=["securityhub:DescribeHub", "guardduty:ListDetectors"],
        expected_config={"security_hub_enabled": True, "guardduty_enabled": True},
        observed_config={"security_hub_enabled": hub, "guardduty_enabled": gd},
        evidence=monitoring,
        explanation=(
            "Both AWS Security Hub and GuardDuty are enabled."
            if passed
            else f"Security monitoring incomplete: security_hub={hub}, guardduty={gd}."
        ),
        remediation_guidance="Enable AWS Security Hub and Amazon GuardDuty across all active regions.",
        framework_mappings=["NIST-CSF-DE.CM-09", "ISO27001-A.8.16"],
        data_source=data_source,
    )
