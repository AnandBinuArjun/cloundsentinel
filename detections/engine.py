"""Deterministic CloudTrail & Azure Activity Log normalization, detection rules, and correlation."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any


@dataclass(frozen=True)
class NormalizedCloudEvent:
    event_id: str
    provider: str  # aws | azure
    account_ref: str
    region: str
    event_name: str
    actor_identity: str
    source_ip: str | None
    event_time: datetime
    parameters: dict[str, Any] = field(default_factory=dict)
    raw_event: dict[str, Any] = field(default_factory=dict)
    data_source: str = "live"


@dataclass(frozen=True)
class DetectionRuleDefinition:
    rule_id: str
    provider: str
    name: str
    description: str
    severity: str
    confidence: str
    mitre_tactic: str
    mitre_technique: str
    event_names: tuple[str, ...]
    version: str = "1.0.0"


@dataclass(frozen=True)
class TriggeredDetection:
    rule: DetectionRuleDefinition
    event: NormalizedCloudEvent
    explanation: str
    correlated_event_ids: list[str]
    evidence_payload: dict[str, Any]


DETECTION_RULES: tuple[DetectionRuleDefinition, ...] = (
    DetectionRuleDefinition(
        rule_id="DET-AWS-001",
        provider="aws",
        name="AWS CloudTrail Logging Disabled or Deleted",
        description="Detects StopLogging, DeleteTrail, or UpdateTrail tampering attempts.",
        severity="critical",
        confidence="high",
        mitre_tactic="Defense Evasion",
        mitre_technique="T1562.008",
        event_names=("StopLogging", "DeleteTrail", "UpdateTrail"),
    ),
    DetectionRuleDefinition(
        rule_id="DET-AWS-002",
        provider="aws",
        name="AWS IAM Policy Privilege Escalation Change",
        description="Detects administrative or wildcard policy attachment/modification events.",
        severity="high",
        confidence="high",
        mitre_tactic="Privilege Escalation",
        mitre_technique="T1098",
        event_names=(
            "AttachUserPolicy",
            "AttachRolePolicy",
            "PutUserPolicy",
            "PutRolePolicy",
            "CreatePolicyVersion",
        ),
    ),
    DetectionRuleDefinition(
        rule_id="DET-AWS-003",
        provider="aws",
        name="AWS Security Group Opened to Public Internet",
        description="Detects AuthorizeSecurityGroupIngress exposing ports to 0.0.0.0/0 or ::/0.",
        severity="high",
        confidence="high",
        mitre_tactic="Defense Evasion",
        mitre_technique="T1562.007",
        event_names=("AuthorizeSecurityGroupIngress",),
    ),
    DetectionRuleDefinition(
        rule_id="DET-AWS-004",
        provider="aws",
        name="Suspicious AWS Console Authentication Without MFA",
        description="Detects root or IAM ConsoleLogin events where MFA was not used.",
        severity="high",
        confidence="medium",
        mitre_tactic="Initial Access",
        mitre_technique="T1078.004",
        event_names=("ConsoleLogin",),
    ),
    DetectionRuleDefinition(
        rule_id="DET-AWS-005",
        provider="aws",
        name="AWS IAM Access Key or User Creation",
        description="Detects CreateAccessKey or CreateUser persistence activity.",
        severity="medium",
        confidence="medium",
        mitre_tactic="Persistence",
        mitre_technique="T1136.003",
        event_names=("CreateAccessKey", "CreateUser"),
    ),
    DetectionRuleDefinition(
        rule_id="DET-AZ-001",
        provider="azure",
        name="Azure Privileged RBAC Role Assignment",
        description="Detects Microsoft.Authorization/roleAssignments/write granting elevated roles.",
        severity="high",
        confidence="high",
        mitre_tactic="Privilege Escalation",
        mitre_technique="T1098.003",
        event_names=("Microsoft.Authorization/roleAssignments/write",),
    ),
    DetectionRuleDefinition(
        rule_id="DET-AZ-002",
        provider="azure",
        name="Azure Network Security Group Rule Modified",
        description="Detects permissive inbound NSG rule creation or modification.",
        severity="high",
        confidence="high",
        mitre_tactic="Defense Evasion",
        mitre_technique="T1562.007",
        event_names=("Microsoft.Network/networkSecurityGroups/securityRules/write",),
    ),
    DetectionRuleDefinition(
        rule_id="DET-AZ-003",
        provider="azure",
        name="Azure Storage Account Public Access Enabled",
        description="Detects Storage account write enabling anonymous blob public access.",
        severity="critical",
        confidence="high",
        mitre_tactic="Collection",
        mitre_technique="T1530",
        event_names=("Microsoft.Storage/storageAccounts/write",),
    ),
    DetectionRuleDefinition(
        rule_id="DET-AZ-004",
        provider="azure",
        name="Azure Diagnostic Settings Deleted",
        description="Detects removal of Activity Log or resource diagnostic settings.",
        severity="critical",
        confidence="high",
        mitre_tactic="Defense Evasion",
        mitre_technique="T1562.008",
        event_names=("Microsoft.Insights/diagnosticSettings/delete",),
    ),
)


def normalize_aws_cloudtrail_event(
    raw: dict[str, Any], data_source: str = "live"
) -> NormalizedCloudEvent:
    """Normalize a raw AWS CloudTrail management event record."""
    event_time_raw = str(raw.get("eventTime", datetime.now(UTC).isoformat()))
    parsed_time = datetime.fromisoformat(event_time_raw.replace("Z", "+00:00"))
    user_identity = raw.get("userIdentity", {})
    actor = str(
        user_identity.get("arn")
        or user_identity.get("userName")
        or user_identity.get("type")
        or "unknown-aws-actor"
    )
    return NormalizedCloudEvent(
        event_id=str(raw.get("eventID", f"ct-{parsed_time.timestamp()}")),
        provider="aws",
        account_ref=str(
            raw.get("recipientAccountId") or user_identity.get("accountId") or "unknown"
        ),
        region=str(raw.get("awsRegion", "us-east-1")),
        event_name=str(raw.get("eventName", "UnknownEvent")),
        actor_identity=actor,
        source_ip=str(raw["sourceIPAddress"]) if raw.get("sourceIPAddress") else None,
        event_time=parsed_time,
        parameters=dict(raw.get("requestParameters") or {}),
        raw_event=dict(raw),
        data_source=data_source,
    )


def normalize_azure_activity_event(
    raw: dict[str, Any], data_source: str = "live"
) -> NormalizedCloudEvent:
    """Normalize a raw Azure Activity Log event record."""
    event_time_raw = str(raw.get("eventTimestamp", datetime.now(UTC).isoformat()))
    parsed_time = datetime.fromisoformat(event_time_raw.replace("Z", "+00:00"))
    op_name = raw.get("operationName", {})
    event_name = str(op_name.get("value") if isinstance(op_name, dict) else op_name)
    return NormalizedCloudEvent(
        event_id=str(raw.get("eventDataId", f"az-{parsed_time.timestamp()}")),
        provider="azure",
        account_ref=str(raw.get("subscriptionId", "unknown")),
        region=str(raw.get("location", "global")),
        event_name=event_name,
        actor_identity=str(raw.get("caller", "unknown-azure-caller")),
        source_ip=str(raw.get("httpRequest", {}).get("clientIpAddress"))
        if isinstance(raw.get("httpRequest"), dict) and raw["httpRequest"].get("clientIpAddress")
        else None,
        event_time=parsed_time,
        parameters=dict(raw.get("properties") or {}),
        raw_event=dict(raw),
        data_source=data_source,
    )


def _matches_rule(rule: DetectionRuleDefinition, event: NormalizedCloudEvent) -> tuple[bool, str]:
    if event.provider != rule.provider or event.event_name not in rule.event_names:
        return False, ""

    params = event.parameters
    if rule.rule_id == "DET-AWS-003":
        cidr = str(params.get("cidrIp", "")) + str(params.get("ipPermissions", ""))
        if "0.0.0.0/0" in cidr or "::/0" in cidr:
            return (
                True,
                f"Actor {event.actor_identity} opened security group ingress to public CIDR.",
            )
        return False, ""

    if rule.rule_id == "DET-AWS-004":
        mfa_used = str(event.raw_event.get("additionalEventData", {}).get("MFAUsed", "No"))
        if mfa_used.lower() != "yes":
            return True, f"ConsoleLogin succeeded/attempted for {event.actor_identity} without MFA."
        return False, ""

    if rule.rule_id == "DET-AZ-003":
        if params.get("allowBlobPublicAccess") is True:
            return (
                True,
                f"Caller {event.actor_identity} enabled anonymous blob public access on storage account.",
            )
        return False, ""

    return (
        True,
        f"Deterministic rule {rule.rule_id} matched {event.event_name} by {event.actor_identity}.",
    )


def evaluate_events(
    events: list[NormalizedCloudEvent],
    *,
    correlation_window_minutes: int = 30,
) -> list[TriggeredDetection]:
    """Evaluate normalized events against the deterministic registry and correlate actor bursts."""
    # Group events by (provider, account_ref, actor_identity) for time-window correlation.
    by_actor: dict[tuple[str, str, str], list[NormalizedCloudEvent]] = defaultdict(list)
    for ev in events:
        by_actor[(ev.provider, ev.account_ref, ev.actor_identity)].append(ev)

    window = timedelta(minutes=correlation_window_minutes)
    detections: list[TriggeredDetection] = []

    for ev in events:
        actor_events = by_actor[(ev.provider, ev.account_ref, ev.actor_identity)]
        correlated_ids = [
            other.event_id
            for other in actor_events
            if other.event_id != ev.event_id and abs(other.event_time - ev.event_time) <= window
        ]
        for rule in DETECTION_RULES:
            matched, explanation = _matches_rule(rule, ev)
            if matched:
                if correlated_ids:
                    explanation = (
                        f"{explanation} Correlated with {len(correlated_ids)} related event(s) "
                        f"from the same identity within {correlation_window_minutes}m."
                    )
                detections.append(
                    TriggeredDetection(
                        rule=rule,
                        event=ev,
                        explanation=explanation,
                        correlated_event_ids=correlated_ids,
                        evidence_payload={
                            "event_id": ev.event_id,
                            "event_name": ev.event_name,
                            "actor_identity": ev.actor_identity,
                            "source_ip": ev.source_ip,
                            "parameters": ev.parameters,
                        },
                    )
                )
    return detections
