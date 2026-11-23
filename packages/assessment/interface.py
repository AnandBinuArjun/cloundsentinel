"""Common cloud provider interface and canonical assessment contracts."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class CheckStatus(StrEnum):
    """Canonical deterministic evaluation outcomes.

    Never coerce an API error or missing permission into PASS.
    """

    PASS = "PASS"  # noqa: S105
    FAIL = "FAIL"
    NOT_ASSESSED = "NOT_ASSESSED"
    ERROR = "ERROR"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class PreflightResult:
    valid: bool
    provider: str
    account_or_subscription_id: str
    identity_arn_or_principal: str
    auth_mode: str
    data_source: str
    checked_permissions: dict[str, str]  # permission -> ok | denied | not_checked
    errors: list[str] = field(default_factory=list)
    validated_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True)
class DiscoveredAsset:
    provider: str
    account_ref: str
    resource_id: str
    resource_name: str
    resource_type: str
    region: str
    tags: dict[str, Any]
    configuration: dict[str, Any]
    collection_status: str = "collected"
    data_source: str = "live"


@dataclass(frozen=True)
class CheckEvaluation:
    rule_id: str
    rule_version: str
    provider: str
    account_ref: str
    resource_id: str
    resource_type: str
    region: str
    title: str
    description: str
    status: CheckStatus
    severity: Severity
    confidence: Confidence
    required_permissions: list[str]
    expected_config: dict[str, Any]
    observed_config: dict[str, Any]
    evidence: dict[str, Any]
    explanation: str
    remediation_guidance: str
    framework_mappings: list[str]
    internet_exposed: bool = False
    asset_criticality: str = "standard"  # high | standard | low
    identity_privilege: str = "none"  # admin | elevated | standard | none
    limitations: str | None = None
    data_source: str = "live"


@dataclass(frozen=True)
class IdentityRiskItem:
    provider: str
    account_ref: str
    principal_id: str
    principal_type: str
    risk_category: str
    severity: Severity
    evidence: dict[str, Any]
    recommendation: str


@dataclass(frozen=True)
class IdentityAnalysisReport:
    provider: str
    account_ref: str
    data_source: str
    principals_reviewed: int
    findings: list[IdentityRiskItem]
    limitations: list[str]
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class CollectionReport:
    assets: list[DiscoveredAsset]
    evaluations: list[CheckEvaluation]
    partial_failures: list[dict[str, Any]]
    data_source: str = "live"


class CloudProviderConnector(ABC):
    """Common read-only provider interface shared by AWS and Azure connectors."""

    provider: str

    @abstractmethod
    def validate_connection(self) -> PreflightResult:
        """Verify identity, account/subscription scope, and read-only preflight permissions."""

    @abstractmethod
    def collect_and_assess(self) -> CollectionReport:
        """Discover authorized assets and evaluate deterministic security checks."""

    @abstractmethod
    def analyze_identities(self) -> IdentityAnalysisReport:
        """Analyze IAM / Azure RBAC identity posture and explicitly report limitations."""
