"""Explicitly labeled synthetic AWS provider response fixtures for CI and local demos."""

from __future__ import annotations

from typing import Any


def get_synthetic_aws_snapshot(account_id: str = "123456789012") -> dict[str, Any]:
    """Return a deterministic synthetic AWS account snapshot (NEVER live cloud data)."""
    return {
        "account_id": account_id,
        "caller_arn": f"arn:aws:sts::{account_id}:assumed-role/CloudSentinelReadOnlyRole/fixture-session",
        "s3_buckets": [
            {
                "name": f"acme-public-exports-{account_id}",
                "region": "us-east-1",
                "tags": {"Environment": "staging", "Owner": "data-eng"},
                "public_access_block": {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                },
                "encryption": {"enabled": False},
                "policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "PublicRead",
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "s3:GetObject",
                            "Resource": f"arn:aws:s3:::acme-public-exports-{account_id}/*",
                        }
                    ],
                },
            },
            {
                "name": f"acme-audit-archive-{account_id}",
                "region": "us-east-1",
                "tags": {"Environment": "prod", "Classification": "restricted"},
                "public_access_block": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
                "encryption": {"enabled": True, "algorithm": "aws:kms"},
                "policy": {"Version": "2012-10-17", "Statement": []},
            },
        ],
        "ec2_instances": [
            {
                "instance_id": "i-0a1b2c3d4e5f60001",
                "name": "bastion-legacy-01",
                "region": "us-east-1",
                "state": "running",
                "public_ip": "198.51.100.24",
                "tags": {"Environment": "prod", "Role": "bastion"},
            }
        ],
        "security_groups": [
            {
                "group_id": "sg-0123456789abcdef0",
                "group_name": "legacy-ssh-rdp-open",
                "region": "us-east-1",
                "tags": {"Environment": "prod"},
                "ingress_rules": [
                    {"from_port": 22, "to_port": 22, "protocol": "tcp", "cidrs": ["0.0.0.0/0"]},
                    {"from_port": 3389, "to_port": 3389, "protocol": "tcp", "cidrs": ["0.0.0.0/0"]},
                ],
            },
            {
                "group_id": "sg-0fedcba9876543210",
                "group_name": "internal-app-sg",
                "region": "us-east-1",
                "tags": {"Environment": "prod"},
                "ingress_rules": [
                    {"from_port": 443, "to_port": 443, "protocol": "tcp", "cidrs": ["10.0.0.0/8"]},
                ],
            },
        ],
        "ebs_volumes": [
            {
                "volume_id": "vol-0abc1111222233334",
                "region": "us-east-1",
                "encrypted": False,
                "size_gb": 100,
                "tags": {"Environment": "prod"},
            },
            {
                "volume_id": "vol-0def5555666677778",
                "region": "us-east-1",
                "encrypted": True,
                "size_gb": 50,
                "tags": {"Environment": "prod"},
            },
        ],
        "cloudtrail_trails": [
            {
                "name": "regional-only-trail",
                "is_multi_region": False,
                "is_logging": True,
            }
        ],
        "iam_policies": [
            {
                "name": "DevOpsFullWildcardPolicy",
                "arn": f"arn:aws:iam::{account_id}:policy/DevOpsFullWildcardPolicy",
                "document": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
                },
            }
        ],
        "iam_users": [
            {
                "username": "legacy-ci-admin",
                "arn": f"arn:aws:iam::{account_id}:user/legacy-ci-admin",
                "console_access": True,
                "mfa_enabled": False,
                "oldest_active_key_age_days": 145,
                "has_admin_policy": True,
            },
            {
                "username": "sec-auditor",
                "arn": f"arn:aws:iam::{account_id}:user/sec-auditor",
                "console_access": True,
                "mfa_enabled": True,
                "oldest_active_key_age_days": 30,
                "has_admin_policy": False,
            },
        ],
        "iam_roles": [
            {
                "role_name": "RiskyCrossAccountRole",
                "arn": f"arn:aws:iam::{account_id}:role/RiskyCrossAccountRole",
                "trust_policy": {
                    "Statement": [
                        {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}
                    ]
                },
            }
        ],
        "security_monitoring": {
            "security_hub_enabled": False,
            "guardduty_enabled": True,
        },
    }
