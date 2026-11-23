"""Replayable synthetic CloudTrail and Azure Activity Log detection test fixtures."""

from __future__ import annotations

from typing import Any

SYNTHETIC_AWS_CLOUDTRAIL_EVENTS: list[dict[str, Any]] = [
    {
        "eventID": "ct-fixture-001",
        "eventTime": "2026-11-23T12:00:00Z",
        "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "eventName": "ConsoleLogin",
        "sourceIPAddress": "203.0.113.45",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/legacy-ci-admin",
        },
        "additionalEventData": {"MFAUsed": "No"},
        "requestParameters": {},
    },
    {
        "eventID": "ct-fixture-002",
        "eventTime": "2026-11-23T12:05:00Z",
        "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "eventName": "StopLogging",
        "sourceIPAddress": "203.0.113.45",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/legacy-ci-admin",
        },
        "requestParameters": {"name": "arn:aws:cloudtrail:us-east-1:123456789012:trail/prod-trail"},
    },
    {
        "eventID": "ct-fixture-003",
        "eventTime": "2026-11-23T12:08:00Z",
        "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "eventName": "AuthorizeSecurityGroupIngress",
        "sourceIPAddress": "203.0.113.45",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/legacy-ci-admin",
        },
        "requestParameters": {
            "groupId": "sg-0123456789abcdef0",
            "cidrIp": "0.0.0.0/0",
            "fromPort": 22,
        },
    },
]

SYNTHETIC_AZURE_ACTIVITY_EVENTS: list[dict[str, Any]] = [
    {
        "eventDataId": "az-fixture-001",
        "eventTimestamp": "2026-11-23T12:15:00Z",
        "subscriptionId": "00000000-1111-2222-3333-444444444444",
        "location": "eastus",
        "operationName": {"value": "Microsoft.Authorization/roleAssignments/write"},
        "caller": "sp-automation-owner-01",
        "httpRequest": {"clientIpAddress": "198.51.100.77"},
        "properties": {
            "roleDefinitionName": "Owner",
            "scope": "/subscriptions/00000000-1111-2222-3333-444444444444",
        },
    },
    {
        "eventDataId": "az-fixture-002",
        "eventTimestamp": "2026-11-23T12:18:00Z",
        "subscriptionId": "00000000-1111-2222-3333-444444444444",
        "location": "eastus",
        "operationName": {"value": "Microsoft.Storage/storageAccounts/write"},
        "caller": "sp-automation-owner-01",
        "httpRequest": {"clientIpAddress": "198.51.100.77"},
        "properties": {"storageAccount": "stacmelegacy01", "allowBlobPublicAccess": True},
    },
]
