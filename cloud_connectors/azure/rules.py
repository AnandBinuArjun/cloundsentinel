"""Deterministic Microsoft Azure security posture rules (8 core checks)."""

from __future__ import annotations

from typing import Any

from packages.assessment.interface import (
    CheckEvaluation,
    CheckStatus,
    Confidence,
    Severity,
)

RULE_VERSION = "1.0.0"


def evaluate_azure_storage_account(
    *,
    subscription_id: str,
    account: dict[str, Any],
    data_source: str,
) -> list[CheckEvaluation]:
    """Evaluate AZ-STG-001 (anonymous blob), AZ-STG-002 (HTTPS/TLS), AZ-STG-003 (encryption)."""
    res_id = str(account["id"])
    region = str(account.get("location", "eastus"))
    results: list[CheckEvaluation] = []

    allow_public = bool(account.get("allow_blob_public_access", True))
    results.append(
        CheckEvaluation(
            rule_id="AZ-STG-001",
            rule_version=RULE_VERSION,
            provider="azure",
            account_ref=subscription_id,
            resource_id=res_id,
            resource_type="azure_storage_account",
            region=region,
            title="Azure Storage account must disable anonymous blob public access",
            description="Ensures allowBlobPublicAccess is set to false on Azure Storage accounts.",
            status=CheckStatus.FAIL if allow_public else CheckStatus.PASS,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            required_permissions=["Microsoft.Storage/storageAccounts/read"],
            expected_config={"allowBlobPublicAccess": False},
            observed_config={"allowBlobPublicAccess": allow_public},
            evidence={
                "storage_account": account.get("name"),
                "allowBlobPublicAccess": allow_public,
            },
            explanation=(
                "Storage account permits anonymous public blob access."
                if allow_public
                else "Anonymous public blob access is disabled."
            ),
            remediation_guidance="Set allowBlobPublicAccess=false on the Storage Account and remove public container access levels.",
            framework_mappings=["CIS-AZURE-3.7", "NIST-CSF-PR.DS-01", "ISO27001-A.8.3"],
            internet_exposed=allow_public,
            asset_criticality="high",
            data_source=data_source,
        )
    )

    https_only = bool(account.get("supports_https_traffic_only", False))
    min_tls = str(account.get("minimum_tls_version", "TLS1_0"))
    tls_ok = https_only and min_tls in ("TLS1_2", "TLS1_3")
    results.append(
        CheckEvaluation(
            rule_id="AZ-STG-002",
            rule_version=RULE_VERSION,
            provider="azure",
            account_ref=subscription_id,
            resource_id=res_id,
            resource_type="azure_storage_account",
            region=region,
            title="Azure Storage account must enforce HTTPS-only transfer and TLS 1.2+",
            description="Checks supportsHttpsTrafficOnly=true and minimumTlsVersion>=TLS1_2.",
            status=CheckStatus.PASS if tls_ok else CheckStatus.FAIL,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            required_permissions=["Microsoft.Storage/storageAccounts/read"],
            expected_config={"supportsHttpsTrafficOnly": True, "minimumTlsVersion": "TLS1_2"},
            observed_config={"supportsHttpsTrafficOnly": https_only, "minimumTlsVersion": min_tls},
            evidence={
                "storage_account": account.get("name"),
                "https_only": https_only,
                "min_tls": min_tls,
            },
            explanation=(
                "HTTPS-only and TLS 1.2+ are enforced."
                if tls_ok
                else f"Insecure transport config: supportsHttpsTrafficOnly={https_only}, minimumTlsVersion={min_tls}."
            ),
            remediation_guidance="Enable Secure Transfer Required and set Minimum TLS Version to TLS 1.2.",
            framework_mappings=[
                "CIS-AZURE-3.1",
                "CIS-AZURE-3.15",
                "NIST-CSF-PR.DS-02",
                "ISO27001-A.8.24",
            ],
            asset_criticality="high",
            data_source=data_source,
        )
    )

    infra_enc = bool(account.get("require_infrastructure_encryption", False))
    blob_enc = bool(account.get("encryption_enabled", True))
    enc_ok = blob_enc and infra_enc
    results.append(
        CheckEvaluation(
            rule_id="AZ-STG-003",
            rule_version=RULE_VERSION,
            provider="azure",
            account_ref=subscription_id,
            resource_id=res_id,
            resource_type="azure_storage_account",
            region=region,
            title="Azure Storage account must enforce encryption protections",
            description="Checks storage service encryption and double infrastructure encryption posture.",
            status=CheckStatus.PASS if enc_ok else CheckStatus.FAIL,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            required_permissions=["Microsoft.Storage/storageAccounts/read"],
            expected_config={"encryption_enabled": True, "require_infrastructure_encryption": True},
            observed_config={
                "encryption_enabled": blob_enc,
                "require_infrastructure_encryption": infra_enc,
            },
            evidence={
                "storage_account": account.get("name"),
                "encryption_enabled": blob_enc,
                "infra_encryption": infra_enc,
            },
            explanation=(
                "Storage account encryption and infrastructure encryption are enabled."
                if enc_ok
                else "Storage account lacks double infrastructure encryption or customer-managed key protection."
            ),
            remediation_guidance="Enable infrastructure encryption and configure customer-managed keys (CMK) in Azure Key Vault.",
            framework_mappings=["CIS-AZURE-3.2", "NIST-CSF-PR.DS-01", "ISO27001-A.8.24"],
            data_source=data_source,
        )
    )
    return results


def evaluate_azure_nsg(
    *,
    subscription_id: str,
    nsg: dict[str, Any],
    data_source: str,
) -> CheckEvaluation:
    """Evaluate AZ-NET-001: Unrestricted NSG inbound rules."""
    res_id = str(nsg["id"])
    region = str(nsg.get("location", "eastus"))
    offending = []
    for rule in nsg.get("security_rules", []):
        if rule.get("direction") != "Inbound" or rule.get("access") != "Allow":
            continue
        src = str(rule.get("source_address_prefix", ""))
        port = str(rule.get("destination_port_range", ""))
        if src in ("*", "0.0.0.0/0", "Internet", "Any") and port in ("*", "22", "3389", "0-65535"):
            offending.append(rule)

    failed = bool(offending)
    return CheckEvaluation(
        rule_id="AZ-NET-001",
        rule_version=RULE_VERSION,
        provider="azure",
        account_ref=subscription_id,
        resource_id=res_id,
        resource_type="azure_nsg",
        region=region,
        title="Network Security Group must not allow unrestricted inbound management ports",
        description="Detects NSG inbound Allow rules exposing SSH (22), RDP (3389), or all ports (*) to Internet/Any.",
        status=CheckStatus.FAIL if failed else CheckStatus.PASS,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        required_permissions=["Microsoft.Network/networkSecurityGroups/read"],
        expected_config={"unrestricted_inbound_rules": 0},
        observed_config={"unrestricted_inbound_rules": len(offending), "rules": offending},
        evidence={"nsg": nsg.get("name"), "offending_rules": offending},
        explanation=(
            f"NSG {nsg.get('name')} has {len(offending)} unrestricted inbound Allow rule(s)."
            if failed
            else f"NSG {nsg.get('name')} has no unrestricted public inbound management rules."
        ),
        remediation_guidance="Restrict NSG sourceAddressPrefix to trusted IPs or use Azure Bastion / JIT VM access.",
        framework_mappings=[
            "CIS-AZURE-6.1",
            "CIS-AZURE-6.2",
            "NIST-CSF-PR.IR-01",
            "ISO27001-A.8.20",
        ],
        internet_exposed=failed,
        asset_criticality="high" if failed else "standard",
        data_source=data_source,
    )


def evaluate_azure_rbac(
    *,
    subscription_id: str,
    assignments: list[dict[str, Any]],
    data_source: str,
) -> CheckEvaluation:
    """Evaluate AZ-IAM-001: Excessive privileged RBAC role assignments at subscription scope."""
    privileged = [
        a
        for a in assignments
        if a.get("role_name") in ("Owner", "User Access Administrator")
        and str(a.get("scope", "")).endswith(f"/subscriptions/{subscription_id}")
    ]
    failed = len(privileged) > 2
    return CheckEvaluation(
        rule_id="AZ-IAM-001",
        rule_version=RULE_VERSION,
        provider="azure",
        account_ref=subscription_id,
        resource_id=f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleAssignments",
        resource_type="azure_rbac_scope",
        region="global",
        title="Subscription-wide Owner/User Access Administrator assignments must be minimized",
        description="Flags subscriptions with more than 2 standing Owner or User Access Administrator assignments.",
        status=CheckStatus.FAIL if failed else CheckStatus.PASS,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        required_permissions=["Microsoft.Authorization/roleAssignments/read"],
        expected_config={"max_subscription_owners": 2},
        observed_config={"subscription_privileged_assignments": len(privileged)},
        evidence={"privileged_assignments": privileged},
        explanation=(
            f"Found {len(privileged)} standing Owner/User Access Administrator assignments at subscription scope."
            if failed
            else f"Subscription privileged assignments ({len(privileged)}) within threshold."
        ),
        remediation_guidance="Replace standing Owner roles with least-privilege resource-group roles and Microsoft Entra PIM.",
        framework_mappings=["CIS-AZURE-1.23", "NIST-CSF-PR.AA-05", "ISO27001-A.8.2"],
        identity_privilege="admin" if failed else "elevated",
        limitations="Does not inspect Entra ID PIM eligible assignments without Microsoft Graph PrivilegedAccess.Read permissions.",
        data_source=data_source,
    )


def evaluate_azure_key_vault(
    *,
    subscription_id: str,
    vault: dict[str, Any],
    data_source: str,
) -> CheckEvaluation:
    """Evaluate AZ-KV-001: Key Vault RBAC, soft-delete, purge protection, and network posture."""
    res_id = str(vault["id"])
    region = str(vault.get("location", "eastus"))
    issues: list[str] = []
    if not vault.get("enable_rbac_authorization", False):
        issues.append("Azure RBAC authorization not enabled (legacy access policies active)")
    if not vault.get("enable_purge_protection", False):
        issues.append("Purge protection disabled")
    if vault.get("public_network_access", "Enabled") == "Enabled":
        issues.append("Public network access enabled")

    failed = bool(issues)
    return CheckEvaluation(
        rule_id="AZ-KV-001",
        rule_version=RULE_VERSION,
        provider="azure",
        account_ref=subscription_id,
        resource_id=res_id,
        resource_type="azure_key_vault",
        region=region,
        title="Azure Key Vault must enforce RBAC, purge protection, and private networking",
        description="Evaluates Key Vault authorization model, purge protection, and public network exposure.",
        status=CheckStatus.FAIL if failed else CheckStatus.PASS,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        required_permissions=["Microsoft.KeyVault/vaults/read"],
        expected_config={
            "enable_rbac_authorization": True,
            "enable_purge_protection": True,
            "public_network_access": "Disabled",
        },
        observed_config={
            "enable_rbac_authorization": vault.get("enable_rbac_authorization"),
            "enable_purge_protection": vault.get("enable_purge_protection"),
            "public_network_access": vault.get("public_network_access"),
        },
        evidence={"vault": vault.get("name"), "issues": issues},
        explanation="; ".join(issues)
        if failed
        else f"Key Vault {vault.get('name')} meets hardening baseline.",
        remediation_guidance="Enable RBAC authorization, enable purge protection, and restrict access via Private Endpoints.",
        framework_mappings=[
            "CIS-AZURE-8.4",
            "CIS-AZURE-8.5",
            "NIST-CSF-PR.DS-01",
            "ISO27001-A.8.24",
        ],
        internet_exposed=vault.get("public_network_access") == "Enabled",
        asset_criticality="high",
        data_source=data_source,
    )


def evaluate_azure_diagnostics_and_monitoring(
    *,
    subscription_id: str,
    diagnostics: dict[str, Any],
    defender: dict[str, Any],
    data_source: str,
) -> list[CheckEvaluation]:
    """Evaluate AZ-MON-001 (diagnostic settings) and AZ-MON-002 (Defender for Cloud)."""
    diag_enabled = bool(diagnostics.get("activity_log_exported", False))
    defender_enabled = bool(defender.get("standard_tier_enabled", False))

    return [
        CheckEvaluation(
            rule_id="AZ-MON-001",
            rule_version=RULE_VERSION,
            provider="azure",
            account_ref=subscription_id,
            resource_id=f"/subscriptions/{subscription_id}/providers/Microsoft.Insights/diagnosticSettings",
            resource_type="azure_diagnostic_settings",
            region="global",
            title="Azure subscription must export Activity Logs via Diagnostic Settings",
            description="Ensures Activity Logs are archived to Log Analytics, Storage, or Event Hub.",
            status=CheckStatus.PASS if diag_enabled else CheckStatus.FAIL,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            required_permissions=["Microsoft.Insights/diagnosticSettings/read"],
            expected_config={"activity_log_exported": True},
            observed_config=diagnostics,
            evidence=diagnostics,
            explanation=(
                "Subscription Activity Log diagnostic settings configured."
                if diag_enabled
                else "No subscription Activity Log diagnostic setting export detected."
            ),
            remediation_guidance="Configure subscription Diagnostic Settings exporting Administrative, Security, and Policy logs.",
            framework_mappings=["CIS-AZURE-5.1.1", "NIST-CSF-DE.CM-01", "ISO27001-A.8.15"],
            data_source=data_source,
        ),
        CheckEvaluation(
            rule_id="AZ-MON-002",
            rule_version=RULE_VERSION,
            provider="azure",
            account_ref=subscription_id,
            resource_id=f"/subscriptions/{subscription_id}/providers/Microsoft.Security/pricings",
            resource_type="azure_defender_for_cloud",
            region="global",
            title="Microsoft Defender for Cloud monitoring must be enabled",
            description="Checks whether Defender for Cloud plans are enabled for the subscription.",
            status=CheckStatus.PASS if defender_enabled else CheckStatus.FAIL,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            required_permissions=["Microsoft.Security/pricings/read"],
            expected_config={"standard_tier_enabled": True},
            observed_config=defender,
            evidence=defender,
            explanation=(
                "Microsoft Defender for Cloud Standard tier active."
                if defender_enabled
                else "Microsoft Defender for Cloud Standard tier is not enabled."
            ),
            remediation_guidance="Enable Microsoft Defender for Cloud plans for Servers, Storage, Key Vault, and ARM.",
            framework_mappings=["CIS-AZURE-2.1.1", "NIST-CSF-DE.CM-09", "ISO27001-A.8.16"],
            data_source=data_source,
        ),
    ]
