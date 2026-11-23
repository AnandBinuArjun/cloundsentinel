"""AWS STS read-only cloud connector implementing CloudProviderConnector."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError

from cloud_connectors.aws.fixtures import get_synthetic_aws_snapshot
from cloud_connectors.aws.rules import (
    evaluate_aws_cloudtrail,
    evaluate_aws_ebs_volume,
    evaluate_aws_iam_policy,
    evaluate_aws_iam_user,
    evaluate_aws_s3_bucket,
    evaluate_aws_security_group,
    evaluate_aws_security_monitoring,
)
from packages.assessment.interface import (
    CheckEvaluation,
    CheckStatus,
    CloudProviderConnector,
    CollectionReport,
    Confidence,
    DiscoveredAsset,
    IdentityAnalysisReport,
    IdentityRiskItem,
    PreflightResult,
    Severity,
)

_ROLE_ARN_RE = re.compile(r"^arn:aws(?:-us-gov|-cn)?:iam::(\d{12}):role/[\w+=,.@/-]+$")


class AWSConnector(CloudProviderConnector):
    """Read-only AWS connector using STS AssumeRole with short-lived credentials."""

    provider = "aws"

    def __init__(
        self,
        *,
        account_id: str,
        role_arn: str | None,
        external_id: str | None = None,
        regions: list[str] | None = None,
        data_source: str = "live",
        fixture_snapshot: dict[str, Any] | None = None,
    ) -> None:
        self.account_id = account_id.strip()
        self.role_arn = role_arn.strip() if role_arn else None
        self.external_id = external_id.strip() if external_id else None
        self.regions = regions or ["us-east-1"]
        self.data_source = data_source
        self._fixture_snapshot = fixture_snapshot
        self._boto_config = BotoConfig(
            connect_timeout=5,
            read_timeout=15,
            retries={"max_attempts": 3, "mode": "standard"},
        )

    def _validate_role_arn_safety(self) -> list[str]:
        errors: list[str] = []
        if not self.role_arn:
            errors.append("AWS cross-account IAM Role ARN is required.")
            return errors
        if ":root" in self.role_arn:
            errors.append("AWS root credentials or root ARNs are strictly prohibited.")
        match = _ROLE_ARN_RE.match(self.role_arn)
        if not match:
            errors.append("Invalid AWS IAM Role ARN format.")
        elif match.group(1) != self.account_id:
            errors.append("Role ARN account ID does not match expected AWS account ID.")
        return errors

    def _assume_readonly_session(self) -> boto3.Session:
        if not self.role_arn:
            raise ValueError("Missing role_arn for AWS STS AssumeRole.")
        sts_client = boto3.client("sts", config=self._boto_config)
        params: dict[str, Any] = {
            "RoleArn": self.role_arn,
            "RoleSessionName": "CloudSentinelReadOnlyAssessment",
            "DurationSeconds": 900,
        }
        if self.external_id:
            params["ExternalId"] = self.external_id
        assumed = sts_client.assume_role(**params)
        creds = assumed["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )

    def validate_connection(self) -> PreflightResult:
        errors = self._validate_role_arn_safety()
        if errors:
            return PreflightResult(
                valid=False,
                provider="aws",
                account_or_subscription_id=self.account_id,
                identity_arn_or_principal=self.role_arn or "",
                auth_mode="sts_assume_role",
                data_source=self.data_source,
                checked_permissions={"sts:AssumeRole": "denied"},
                errors=errors,
            )

        if self.data_source == "synthetic_fixture":
            snap = self._fixture_snapshot or get_synthetic_aws_snapshot(self.account_id)
            return PreflightResult(
                valid=True,
                provider="aws",
                account_or_subscription_id=self.account_id,
                identity_arn_or_principal=str(snap["caller_arn"]),
                auth_mode="sts_assume_role",
                data_source="synthetic_fixture",
                checked_permissions={
                    "sts:AssumeRole": "ok",
                    "sts:GetCallerIdentity": "ok",
                    "s3:ListAllMyBuckets": "ok",
                    "ec2:DescribeSecurityGroups": "ok",
                    "iam:ListUsers": "ok",
                    "cloudtrail:DescribeTrails": "ok",
                },
                errors=[],
            )

        try:
            session = self._assume_readonly_session()
            identity = session.client("sts", config=self._boto_config).get_caller_identity()
            resolved_account = str(identity.get("Account", ""))
            caller_arn = str(identity.get("Arn", ""))
            if resolved_account != self.account_id:
                return PreflightResult(
                    valid=False,
                    provider="aws",
                    account_or_subscription_id=resolved_account,
                    identity_arn_or_principal=caller_arn,
                    auth_mode="sts_assume_role",
                    data_source="live",
                    checked_permissions={"sts:GetCallerIdentity": "ok"},
                    errors=["Assumed role account ID mismatch."],
                )
            return PreflightResult(
                valid=True,
                provider="aws",
                account_or_subscription_id=resolved_account,
                identity_arn_or_principal=caller_arn,
                auth_mode="sts_assume_role",
                data_source="live",
                checked_permissions={"sts:AssumeRole": "ok", "sts:GetCallerIdentity": "ok"},
                errors=[],
            )
        except (ClientError, BotoCoreError, Exception) as exc:
            return PreflightResult(
                valid=False,
                provider="aws",
                account_or_subscription_id=self.account_id,
                identity_arn_or_principal=self.role_arn or "",
                auth_mode="sts_assume_role",
                data_source="live",
                checked_permissions={"sts:AssumeRole": "denied"},
                errors=[f"AWS STS validation failed ({type(exc).__name__})"],
            )

    def _collect_live_snapshot(self) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """Collect authorized AWS inventory via read-only boto3 paginators with partial-failure tracking."""
        partial_failures: list[dict[str, Any]] = []
        session = self._assume_readonly_session()
        now = datetime.now(UTC)
        snapshot: dict[str, Any] = {
            "account_id": self.account_id,
            "s3_buckets": [],
            "ec2_instances": [],
            "security_groups": [],
            "ebs_volumes": [],
            "cloudtrail_trails": [],
            "iam_policies": [],
            "iam_users": [],
            "iam_roles": [],
            "security_monitoring": {"security_hub_enabled": False, "guardduty_enabled": False},
        }

        # 1. S3 buckets (location, public access block, encryption, policy)
        try:
            s3 = session.client("s3", config=self._boto_config)
            for b in s3.list_buckets().get("Buckets", []):
                bname = b["Name"]
                bucket_region = self.regions[0]
                try:
                    loc = s3.get_bucket_location(Bucket=bname).get("LocationConstraint")
                    if loc == "EU":
                        bucket_region = "eu-west-1"
                    elif isinstance(loc, str) and loc:
                        bucket_region = loc
                    else:
                        bucket_region = "us-east-1"
                except ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "")
                    partial_failures.append(
                        {"service": "s3:GetBucketLocation", "bucket": bname, "error": code}
                    )
                pab: dict[str, Any] | None = None
                enc: dict[str, Any] = {"enabled": False}
                policy_doc: dict[str, Any] = {}
                try:
                    pab = s3.get_public_access_block(Bucket=bname).get(
                        "PublicAccessBlockConfiguration"
                    )
                except ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "")
                    if code != "NoSuchPublicAccessBlockConfiguration":
                        pab = {"error": code}
                try:
                    enc_resp = s3.get_bucket_encryption(Bucket=bname)
                    rules = enc_resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                    if rules:
                        algo = (
                            rules[0]
                            .get("ApplyServerSideEncryptionByDefault", {})
                            .get("SSEAlgorithm", "AES256")
                        )
                        enc = {"enabled": True, "algorithm": algo}
                except ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "")
                    if code != "ServerSideEncryptionConfigurationNotFoundError":
                        enc = {"error": code}
                try:
                    raw_pol = s3.get_bucket_policy(Bucket=bname).get("Policy", "")
                    if raw_pol:
                        policy_doc = json.loads(raw_pol)
                except ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "")
                    if code != "NoSuchBucketPolicy":
                        partial_failures.append(
                            {"service": "s3:GetBucketPolicy", "bucket": bname, "error": code}
                        )
                snapshot["s3_buckets"].append(
                    {
                        "name": bname,
                        "region": bucket_region,
                        "tags": {},
                        "public_access_block": pab,
                        "encryption": enc,
                        "policy": policy_doc,
                    }
                )
        except (ClientError, BotoCoreError) as exc:
            err_code = (
                exc.response.get("Error", {}).get("Code", type(exc).__name__)
                if isinstance(exc, ClientError)
                else type(exc).__name__
            )
            partial_failures.append({"service": "s3", "error": err_code})

        # 2. EC2 instances, Security Groups, EBS volumes per selected region
        for region in self.regions:
            try:
                ec2 = session.client("ec2", region_name=region, config=self._boto_config)
                for page in ec2.get_paginator("describe_instances").paginate():
                    for res in page.get("Reservations", []):
                        for inst in res.get("Instances", []):
                            tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                            snapshot["ec2_instances"].append(
                                {
                                    "instance_id": inst["InstanceId"],
                                    "name": tags.get("Name", inst["InstanceId"]),
                                    "region": region,
                                    "state": inst.get("State", {}).get("Name", "unknown"),
                                    "public_ip": inst.get("PublicIpAddress"),
                                    "tags": tags,
                                }
                            )
                for page in ec2.get_paginator("describe_security_groups").paginate():
                    for sg in page.get("SecurityGroups", []):
                        ingress = []
                        for perm in sg.get("IpPermissions", []):
                            cidrs = [r["CidrIp"] for r in perm.get("IpRanges", [])] + [
                                r["CidrIpv6"] for r in perm.get("Ipv6Ranges", [])
                            ]
                            ingress.append(
                                {
                                    "from_port": perm.get("FromPort", -1),
                                    "to_port": perm.get("ToPort", -1),
                                    "protocol": perm.get("IpProtocol", "-1"),
                                    "cidrs": cidrs,
                                }
                            )
                        snapshot["security_groups"].append(
                            {
                                "group_id": sg["GroupId"],
                                "group_name": sg.get("GroupName", ""),
                                "region": region,
                                "tags": {t["Key"]: t["Value"] for t in sg.get("Tags", [])},
                                "ingress_rules": ingress,
                            }
                        )
                for page in ec2.get_paginator("describe_volumes").paginate():
                    for vol in page.get("Volumes", []):
                        snapshot["ebs_volumes"].append(
                            {
                                "volume_id": vol["VolumeId"],
                                "region": region,
                                "encrypted": bool(vol.get("Encrypted", False)),
                                "size_gb": vol.get("Size", 0),
                                "tags": {t["Key"]: t["Value"] for t in vol.get("Tags", [])},
                            }
                        )
            except (ClientError, BotoCoreError) as exc:
                err_code = (
                    exc.response.get("Error", {}).get("Code", type(exc).__name__)
                    if isinstance(exc, ClientError)
                    else type(exc).__name__
                )
                partial_failures.append({"service": "ec2", "region": region, "error": err_code})

        # 3. CloudTrail trails & logging status
        try:
            ct = session.client("cloudtrail", region_name=self.regions[0], config=self._boto_config)
            for trail in ct.describe_trails(includeShadowTrails=True).get("trailList", []):
                is_logging = False
                try:
                    st = ct.get_trail_status(Name=trail.get("TrailARN", trail["Name"]))
                    is_logging = bool(st.get("IsLogging", False))
                except ClientError as exc:
                    partial_failures.append(
                        {"service": "cloudtrail:GetTrailStatus", "error": type(exc).__name__}
                    )
                snapshot["cloudtrail_trails"].append(
                    {
                        "name": trail.get("Name", ""),
                        "is_multi_region": bool(trail.get("IsMultiRegionTrail", False)),
                        "is_logging": is_logging,
                    }
                )
        except (ClientError, BotoCoreError) as exc:
            err_code = (
                exc.response.get("Error", {}).get("Code", type(exc).__name__)
                if isinstance(exc, ClientError)
                else type(exc).__name__
            )
            partial_failures.append({"service": "cloudtrail", "error": err_code})

        # 4. IAM users, customer-managed policies, and roles
        try:
            iam = session.client("iam", config=self._boto_config)
            for page in iam.get_paginator("list_users").paginate():
                for user in page.get("Users", []):
                    uname = user["UserName"]
                    mfa_devices = iam.list_mfa_devices(UserName=uname).get("MFADevices", [])
                    access_keys = iam.list_access_keys(UserName=uname).get("AccessKeyMetadata", [])
                    oldest_days = 0
                    for key in access_keys:
                        if key.get("Status") == "Active" and isinstance(
                            key.get("CreateDate"), datetime
                        ):
                            age = (now - key["CreateDate"].astimezone(UTC)).days
                            oldest_days = max(oldest_days, age)
                    attached = iam.list_attached_user_policies(UserName=uname).get(
                        "AttachedPolicies", []
                    )
                    has_admin = any(p.get("PolicyName") == "AdministratorAccess" for p in attached)
                    snapshot["iam_users"].append(
                        {
                            "username": uname,
                            "arn": user["Arn"],
                            "console_access": bool(user.get("PasswordLastUsed")),
                            "mfa_enabled": bool(mfa_devices),
                            "oldest_active_key_age_days": oldest_days,
                            "has_admin_policy": has_admin,
                        }
                    )
            for page in iam.get_paginator("list_policies").paginate(Scope="Local"):
                for pol in page.get("Policies", []):
                    ver = iam.get_policy_version(
                        PolicyArn=pol["Arn"], VersionId=pol["DefaultVersionId"]
                    )
                    snapshot["iam_policies"].append(
                        {
                            "name": pol["PolicyName"],
                            "arn": pol["Arn"],
                            "document": ver.get("PolicyVersion", {}).get("Document", {}),
                        }
                    )
            for page in iam.get_paginator("list_roles").paginate():
                for role in page.get("Roles", []):
                    snapshot["iam_roles"].append(
                        {
                            "role_name": role["RoleName"],
                            "arn": role["Arn"],
                            "trust_policy": role.get("AssumeRolePolicyDocument", {}),
                        }
                    )
        except (ClientError, BotoCoreError) as exc:
            err_code = (
                exc.response.get("Error", {}).get("Code", type(exc).__name__)
                if isinstance(exc, ClientError)
                else type(exc).__name__
            )
            partial_failures.append({"service": "iam", "error": err_code})

        # 5. Security Hub & GuardDuty monitoring posture
        mon: dict[str, Any] = {"security_hub_enabled": False, "guardduty_enabled": False}
        try:
            sh = session.client(
                "securityhub", region_name=self.regions[0], config=self._boto_config
            )
            sh.describe_hub()
            mon["security_hub_enabled"] = True
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("AccessDeniedException", "UnauthorizedOperation"):
                mon["permission_denied"] = True
        except BotoCoreError:
            partial_failures.append({"service": "securityhub", "error": "BotoCoreError"})

        try:
            gd = session.client("guardduty", region_name=self.regions[0], config=self._boto_config)
            detectors = gd.list_detectors().get("DetectorIds", [])
            mon["guardduty_enabled"] = bool(detectors)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("AccessDeniedException", "UnauthorizedOperation"):
                mon["permission_denied"] = True
        except BotoCoreError:
            partial_failures.append({"service": "guardduty", "error": "BotoCoreError"})

        snapshot["security_monitoring"] = mon
        return snapshot, partial_failures

    def collect_and_assess(self) -> CollectionReport:
        partial_failures: list[dict[str, Any]] = []
        if self.data_source == "synthetic_fixture":
            snap = self._fixture_snapshot or get_synthetic_aws_snapshot(self.account_id)
        else:
            try:
                snap, partial_failures = self._collect_live_snapshot()
            except Exception as exc:
                return CollectionReport(
                    assets=[],
                    evaluations=[],
                    partial_failures=[{"service": "sts", "error": type(exc).__name__}],
                    data_source="live",
                )

        assets: list[DiscoveredAsset] = []
        evaluations: list[CheckEvaluation] = []

        for bucket in snap.get("s3_buckets", []):
            assets.append(
                DiscoveredAsset(
                    provider="aws",
                    account_ref=self.account_id,
                    resource_id=f"arn:aws:s3:::{bucket['name']}",
                    resource_name=str(bucket["name"]),
                    resource_type="aws_s3_bucket",
                    region=str(bucket.get("region", "us-east-1")),
                    tags=dict(bucket.get("tags", {})),
                    configuration={
                        "public_access_block": bucket.get("public_access_block"),
                        "encryption": bucket.get("encryption"),
                    },
                    data_source=self.data_source,
                )
            )
            evaluations.extend(
                evaluate_aws_s3_bucket(
                    account_id=self.account_id,
                    bucket=bucket,
                    data_source=self.data_source,
                )
            )

        for inst in snap.get("ec2_instances", []):
            region = str(inst.get("region", "us-east-1"))
            assets.append(
                DiscoveredAsset(
                    provider="aws",
                    account_ref=self.account_id,
                    resource_id=f"arn:aws:ec2:{region}:{self.account_id}:instance/{inst['instance_id']}",
                    resource_name=str(inst.get("name", inst["instance_id"])),
                    resource_type="aws_ec2_instance",
                    region=region,
                    tags=dict(inst.get("tags", {})),
                    configuration={"state": inst.get("state"), "public_ip": inst.get("public_ip")},
                    data_source=self.data_source,
                )
            )

        for sg in snap.get("security_groups", []):
            region = str(sg.get("region", "us-east-1"))
            assets.append(
                DiscoveredAsset(
                    provider="aws",
                    account_ref=self.account_id,
                    resource_id=f"arn:aws:ec2:{region}:{self.account_id}:security-group/{sg['group_id']}",
                    resource_name=str(sg.get("group_name", sg["group_id"])),
                    resource_type="aws_security_group",
                    region=region,
                    tags=dict(sg.get("tags", {})),
                    configuration={"ingress_rules": sg.get("ingress_rules", [])},
                    data_source=self.data_source,
                )
            )
            evaluations.extend(
                evaluate_aws_security_group(
                    account_id=self.account_id,
                    sg=sg,
                    data_source=self.data_source,
                )
            )

        for vol in snap.get("ebs_volumes", []):
            region = str(vol.get("region", "us-east-1"))
            assets.append(
                DiscoveredAsset(
                    provider="aws",
                    account_ref=self.account_id,
                    resource_id=f"arn:aws:ec2:{region}:{self.account_id}:volume/{vol['volume_id']}",
                    resource_name=str(vol["volume_id"]),
                    resource_type="aws_ebs_volume",
                    region=region,
                    tags=dict(vol.get("tags", {})),
                    configuration={
                        "encrypted": vol.get("encrypted"),
                        "size_gb": vol.get("size_gb"),
                    },
                    data_source=self.data_source,
                )
            )
            evaluations.append(
                evaluate_aws_ebs_volume(
                    account_id=self.account_id,
                    volume=vol,
                    data_source=self.data_source,
                )
            )

        evaluations.append(
            evaluate_aws_cloudtrail(
                account_id=self.account_id,
                trails=list(snap.get("cloudtrail_trails", [])),
                data_source=self.data_source,
            )
        )

        for policy in snap.get("iam_policies", []):
            assets.append(
                DiscoveredAsset(
                    provider="aws",
                    account_ref=self.account_id,
                    resource_id=str(policy["arn"]),
                    resource_name=str(policy.get("name", policy["arn"])),
                    resource_type="aws_iam_policy",
                    region="global",
                    tags={},
                    configuration={"document": policy.get("document", {})},
                    data_source=self.data_source,
                )
            )
            evaluations.append(
                evaluate_aws_iam_policy(
                    account_id=self.account_id,
                    policy=policy,
                    data_source=self.data_source,
                )
            )

        for user in snap.get("iam_users", []):
            assets.append(
                DiscoveredAsset(
                    provider="aws",
                    account_ref=self.account_id,
                    resource_id=str(user["arn"]),
                    resource_name=str(user["username"]),
                    resource_type="aws_iam_user",
                    region="global",
                    tags={},
                    configuration={
                        "console_access": user.get("console_access"),
                        "mfa_enabled": user.get("mfa_enabled"),
                    },
                    data_source=self.data_source,
                )
            )
            evaluations.append(
                evaluate_aws_iam_user(
                    account_id=self.account_id,
                    user=user,
                    data_source=self.data_source,
                )
            )

        evaluations.append(
            evaluate_aws_security_monitoring(
                account_id=self.account_id,
                monitoring=dict(snap.get("security_monitoring", {})),
                data_source=self.data_source,
            )
        )

        # Emit explicit NOT_ASSESSED / ERROR CheckEvaluations for top-level service collection failures
        failed_services = {
            str(pf.get("service")): str(pf.get("error", "Unknown")) for pf in partial_failures
        }
        for svc_key, rule_specs in (
            (
                "s3",
                [
                    (
                        "AWS-S3-001",
                        "aws_s3_bucket",
                        "S3 bucket public access assessment",
                        ["s3:ListAllMyBuckets", "s3:GetBucketPublicAccessBlock"],
                    )
                ],
            ),
            (
                "ec2",
                [
                    (
                        "AWS-EC2-001",
                        "aws_security_group",
                        "EC2 security group assessment",
                        ["ec2:DescribeSecurityGroups"],
                    ),
                    (
                        "AWS-EBS-001",
                        "aws_ebs_volume",
                        "EBS encryption assessment",
                        ["ec2:DescribeVolumes"],
                    ),
                ],
            ),
            (
                "iam",
                [
                    (
                        "AWS-IAM-001",
                        "aws_iam_policy",
                        "IAM policy wildcard assessment",
                        ["iam:ListPolicies"],
                    ),
                    (
                        "AWS-IAM-002",
                        "aws_iam_user",
                        "IAM user MFA/key rotation assessment",
                        ["iam:ListUsers"],
                    ),
                ],
            ),
        ):
            if svc_key in failed_services:
                err_code = failed_services[svc_key]
                is_perm = any(
                    tok in err_code for tok in ("AccessDenied", "Unauthorized", "AuthFailure")
                )
                eval_status = CheckStatus.NOT_ASSESSED if is_perm else CheckStatus.ERROR
                for r_id, r_type, r_title, r_perms in rule_specs:
                    evaluations.append(
                        CheckEvaluation(
                            rule_id=r_id,
                            rule_version="1.0.0",
                            provider="aws",
                            account_ref=self.account_id,
                            resource_id=f"arn:aws:{svc_key}:global:{self.account_id}:collection-status",
                            resource_type=r_type,
                            region=self.regions[0],
                            title=r_title,
                            description=f"Service collection failed for {svc_key}: {err_code}",
                            status=eval_status,
                            severity=Severity.HIGH,
                            confidence=Confidence.LOW,
                            required_permissions=r_perms,
                            expected_config={"collection_succeeded": True},
                            observed_config={"service": svc_key, "error": err_code},
                            evidence={"service": svc_key, "error": err_code},
                            explanation=f"Unable to evaluate {r_id} because {svc_key} API returned {err_code}.",
                            remediation_guidance=f"Grant read-only {svc_key} permissions to the assessment role.",
                            framework_mappings=[],
                            data_source=self.data_source,
                        )
                    )

        if "cloudtrail" in failed_services:
            err_code = failed_services["cloudtrail"]
            is_perm = any(
                tok in err_code for tok in ("AccessDenied", "Unauthorized", "AuthFailure")
            )
            evaluations = [ev for ev in evaluations if ev.rule_id != "AWS-CT-001"]
            evaluations.append(
                CheckEvaluation(
                    rule_id="AWS-CT-001",
                    rule_version="1.0.0",
                    provider="aws",
                    account_ref=self.account_id,
                    resource_id=f"arn:aws:cloudtrail:global:{self.account_id}:account-logging",
                    resource_type="aws_cloudtrail",
                    region="global",
                    title="Multi-region CloudTrail logging must be enabled",
                    description="Ensures at least one active multi-region CloudTrail trail records management events.",
                    status=CheckStatus.NOT_ASSESSED if is_perm else CheckStatus.ERROR,
                    severity=Severity.HIGH,
                    confidence=Confidence.LOW,
                    required_permissions=["cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus"],
                    expected_config={"active_multi_region_trails": ">=1"},
                    observed_config={"error": err_code},
                    evidence={"service": "cloudtrail", "error": err_code},
                    explanation=f"Unable to verify CloudTrail posture because DescribeTrails returned {err_code}.",
                    remediation_guidance="Grant cloudtrail:DescribeTrails and cloudtrail:GetTrailStatus permissions.",
                    framework_mappings=["CIS-AWS-3.1", "NIST-CSF-DE.CM-01", "ISO27001-A.8.15"],
                    data_source=self.data_source,
                )
            )

        return CollectionReport(
            assets=assets,
            evaluations=evaluations,
            partial_failures=partial_failures,
            data_source=self.data_source,
        )

    def analyze_identities(self) -> IdentityAnalysisReport:
        extra_limitations: list[str] = []
        if self.data_source == "synthetic_fixture":
            snap = self._fixture_snapshot or get_synthetic_aws_snapshot(self.account_id)
        else:
            try:
                snap, partial = self._collect_live_snapshot()
                for pf in partial:
                    if pf.get("service") == "iam":
                        extra_limitations.append(
                            f"Live IAM collection encountered partial error: {pf.get('error')}."
                        )
            except Exception as exc:
                snap = {"iam_users": [], "iam_roles": [], "iam_policies": []}
                extra_limitations.append(
                    f"Live AWS identity collection failed ({type(exc).__name__}); 0 principals could be evaluated."
                )

        items: list[IdentityRiskItem] = []

        for user in snap.get("iam_users", []):
            if user.get("console_access") and not user.get("mfa_enabled"):
                items.append(
                    IdentityRiskItem(
                        provider="aws",
                        account_ref=self.account_id,
                        principal_id=str(user["arn"]),
                        principal_type="iam_user",
                        risk_category="missing_mfa",
                        severity=Severity.HIGH,
                        evidence={"username": user["username"], "mfa_enabled": False},
                        recommendation="Require MFA on console login or migrate to federated SSO.",
                    )
                )
            if user.get("has_admin_policy"):
                items.append(
                    IdentityRiskItem(
                        provider="aws",
                        account_ref=self.account_id,
                        principal_id=str(user["arn"]),
                        principal_type="iam_user",
                        risk_category="administrator_access",
                        severity=Severity.CRITICAL,
                        evidence={"username": user["username"], "has_admin_policy": True},
                        recommendation="Remove direct administrative access from IAM users; use time-bound STS roles.",
                    )
                )

        for role in snap.get("iam_roles", []):
            stmts = role.get("trust_policy", {}).get("Statement", [])
            for stmt in stmts:
                if stmt.get("Effect") == "Allow" and stmt.get("Principal") in ("*", {"AWS": "*"}):
                    items.append(
                        IdentityRiskItem(
                            provider="aws",
                            account_ref=self.account_id,
                            principal_id=str(role["arn"]),
                            principal_type="iam_role",
                            risk_category="risky_trust_policy",
                            severity=Severity.CRITICAL,
                            evidence={"role_name": role["role_name"], "statement": stmt},
                            recommendation="Restrict trust policy Principal to explicit AWS account/role ARNs and require ExternalId.",
                        )
                    )

        return IdentityAnalysisReport(
            provider="aws",
            account_ref=self.account_id,
            data_source=self.data_source,
            principals_reviewed=len(snap.get("iam_users", [])) + len(snap.get("iam_roles", [])),
            findings=items,
            limitations=extra_limitations
            + [
                "Effective permission simulation does not include AWS Organizations Service Control Policies (SCPs) or resource-based policy conditions.",
                "Inline policy evaluation and cross-account transitive role chaining require full IAM Access Analyzer permissions.",
            ],
        )
