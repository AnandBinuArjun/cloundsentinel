"""Microsoft Azure read-only cloud connector implementing CloudProviderConnector.

Supports Managed Identity, Workload Identity Federation, and controlled Service Principal
secret references, using Azure Resource Manager (ARM) REST APIs with pagination, SSRF validation,
bounded timeouts, and partial-failure reporting.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import httpx
from azure.identity import ManagedIdentityCredential, WorkloadIdentityCredential

from cloud_connectors.azure.fixtures import get_synthetic_azure_snapshot
from cloud_connectors.azure.rules import (
    evaluate_azure_diagnostics_and_monitoring,
    evaluate_azure_key_vault,
    evaluate_azure_nsg,
    evaluate_azure_rbac,
    evaluate_azure_storage_account,
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
from packages.common.ssrf import validate_outbound_https_url

ALLOWED_AZURE_AUTH_MODES = frozenset(
    {"managed_identity", "workload_identity", "service_principal_secret_ref"}
)
_ARM_BASE_URL = "https://management.azure.com"

# Well-known built-in Azure RBAC role definition IDs
_BUILTIN_ROLE_NAMES: dict[str, str] = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
    "acdd72a7-3385-48ef-bd42-f606fba81ae7": "Reader",
}


class AzureConnector(CloudProviderConnector):
    """Read-only Azure connector supporting Managed Identity, Workload Identity, and controlled SP."""

    provider = "azure"

    def __init__(
        self,
        *,
        subscription_id: str,
        azure_tenant_id: str | None = None,
        auth_mode: str = "managed_identity",
        azure_client_id: str | None = None,
        data_source: str = "live",
        fixture_snapshot: dict[str, Any] | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        self.subscription_id = subscription_id.strip()
        self.azure_tenant_id = azure_tenant_id.strip() if azure_tenant_id else None
        self.auth_mode = auth_mode.strip()
        self.azure_client_id = azure_client_id.strip() if azure_client_id else None
        self.data_source = data_source
        self._fixture_snapshot = fixture_snapshot
        self._http_client = http_client

    def _validate_scope_and_auth_mode(self) -> list[str]:
        errors: list[str] = []
        try:
            uuid.UUID(self.subscription_id)
        except ValueError:
            errors.append("Azure subscription_id must be a valid UUID.")
        if self.auth_mode not in ALLOWED_AZURE_AUTH_MODES:
            errors.append(
                f"Unsupported Azure auth_mode '{self.auth_mode}'. "
                "Use managed_identity, workload_identity, or service_principal_secret_ref."
            )
        return errors

    def _acquire_arm_token(self) -> str:
        if self.auth_mode == "managed_identity":
            cred: Any = ManagedIdentityCredential(client_id=self.azure_client_id)
        elif self.auth_mode == "workload_identity":
            cred = WorkloadIdentityCredential(
                tenant_id=self.azure_tenant_id,
                client_id=self.azure_client_id,
            )
        else:
            raise PermissionError(
                "Service Principal live mode requires an external secret manager binding; "
                "raw secrets are never stored in database columns."
            )
        token = cred.get_token(f"{_ARM_BASE_URL}/.default")
        if not token or not token.token:
            raise RuntimeError("Empty ARM access token returned.")
        return str(token.token)

    def _arm_get_paginated(
        self,
        client: httpx.Client,
        token: str,
        path: str,
        api_version: str,
        max_pages: int = 20,
        max_retries: int = 3,
    ) -> list[dict[str, Any]]:
        """Execute SSRF-validated, paginated GET requests against Azure Resource Manager with retry/cycle guards."""
        url = validate_outbound_https_url(f"{_ARM_BASE_URL}{path}?api-version={api_version}")
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        items: list[dict[str, Any]] = []
        pages = 0
        visited_urls: set[str] = set()

        while url and pages < max_pages:
            if url in visited_urls:
                raise RuntimeError("Detected cyclic nextLink pagination in Azure ARM response.")
            visited_urls.add(url)

            resp: httpx.Response | None = None
            for attempt in range(max_retries):
                resp = client.get(url, headers=headers, timeout=15.0)
                if resp.status_code in (429, 502, 503, 504) and attempt + 1 < max_retries:
                    retry_after_raw = resp.headers.get("Retry-After", "")
                    delay = (
                        min(float(retry_after_raw), 2.0)
                        if retry_after_raw.isdigit()
                        else min(0.05 * (2**attempt), 1.0)
                    )
                    time.sleep(delay)
                    continue
                break

            if resp is None:
                raise RuntimeError("No HTTP response received from Azure ARM.")
            resp.raise_for_status()
            body = resp.json()
            if isinstance(body, dict) and isinstance(body.get("value"), list):
                items.extend(body["value"])
                next_link = body.get("nextLink")
                url = (
                    validate_outbound_https_url(str(next_link))
                    if isinstance(next_link, str) and next_link.startswith(_ARM_BASE_URL)
                    else ""
                )
            else:
                break
            pages += 1
        return items

    def _collect_live_snapshot(self) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """Enumerate authorized Azure subscription resources via ARM REST APIs."""
        token = self._acquire_arm_token()
        sub = self.subscription_id
        partial_failures: list[dict[str, Any]] = []
        snap: dict[str, Any] = {
            "subscription_id": sub,
            "storage_accounts": [],
            "virtual_machines": [],
            "nsgs": [],
            "vnets": [],
            "key_vaults": [],
            "role_assignments": [],
            "diagnostic_settings": {"activity_log_exported": False},
            "defender_for_cloud": {"standard_tier_enabled": False},
        }

        own_client = self._http_client is None
        client = self._http_client or httpx.Client(timeout=15.0)
        try:
            # 1. Storage Accounts
            try:
                for raw in self._arm_get_paginated(
                    client,
                    token,
                    f"/subscriptions/{sub}/providers/Microsoft.Storage/storageAccounts",
                    "2023-05-01",
                ):
                    props = raw.get("properties", {})
                    enc = props.get("encryption", {})
                    snap["storage_accounts"].append(
                        {
                            "id": raw.get("id", ""),
                            "name": raw.get("name", ""),
                            "location": raw.get("location", "global"),
                            "tags": raw.get("tags") or {},
                            "allow_blob_public_access": props.get("allowBlobPublicAccess", True),
                            "supports_https_traffic_only": props.get(
                                "supportsHttpsTrafficOnly", False
                            ),
                            "minimum_tls_version": props.get("minimumTlsVersion", "TLS1_0"),
                            "encryption_enabled": bool(
                                enc.get("services", {}).get("blob", {}).get("enabled", True)
                            ),
                            "require_infrastructure_encryption": bool(
                                enc.get("requireInfrastructureEncryption", False)
                            ),
                        }
                    )
            except Exception as exc:
                partial_failures.append(
                    {"service": "Microsoft.Storage", "error": type(exc).__name__}
                )

            # 2. Virtual Machines
            try:
                for raw in self._arm_get_paginated(
                    client,
                    token,
                    f"/subscriptions/{sub}/providers/Microsoft.Compute/virtualMachines",
                    "2024-03-01",
                ):
                    snap["virtual_machines"].append(
                        {
                            "id": raw.get("id", ""),
                            "name": raw.get("name", ""),
                            "location": raw.get("location", "global"),
                            "tags": raw.get("tags") or {},
                            "vm_size": raw.get("properties", {})
                            .get("hardwareProfile", {})
                            .get("vmSize"),
                        }
                    )
            except Exception as exc:
                partial_failures.append(
                    {"service": "Microsoft.Compute", "error": type(exc).__name__}
                )

            # 3. Network Security Groups
            try:
                for raw in self._arm_get_paginated(
                    client,
                    token,
                    f"/subscriptions/{sub}/providers/Microsoft.Network/networkSecurityGroups",
                    "2023-11-01",
                ):
                    rules = []
                    for r in raw.get("properties", {}).get("securityRules", []):
                        rp = r.get("properties", {})
                        rules.append(
                            {
                                "name": r.get("name", ""),
                                "direction": rp.get("direction", ""),
                                "access": rp.get("access", ""),
                                "source_address_prefix": rp.get("sourceAddressPrefix", ""),
                                "destination_port_range": rp.get("destinationPortRange", ""),
                            }
                        )
                    snap["nsgs"].append(
                        {
                            "id": raw.get("id", ""),
                            "name": raw.get("name", ""),
                            "location": raw.get("location", "global"),
                            "tags": raw.get("tags") or {},
                            "security_rules": rules,
                        }
                    )
            except Exception as exc:
                partial_failures.append(
                    {"service": "Microsoft.Network/nsg", "error": type(exc).__name__}
                )

            # 4. Virtual Networks
            try:
                for raw in self._arm_get_paginated(
                    client,
                    token,
                    f"/subscriptions/{sub}/providers/Microsoft.Network/virtualNetworks",
                    "2023-11-01",
                ):
                    snap["vnets"].append(
                        {
                            "id": raw.get("id", ""),
                            "name": raw.get("name", ""),
                            "location": raw.get("location", "global"),
                            "tags": raw.get("tags") or {},
                            "address_space": raw.get("properties", {})
                            .get("addressSpace", {})
                            .get("addressPrefixes", []),
                        }
                    )
            except Exception as exc:
                partial_failures.append(
                    {"service": "Microsoft.Network/vnet", "error": type(exc).__name__}
                )

            # 5. Key Vaults
            try:
                for raw in self._arm_get_paginated(
                    client,
                    token,
                    f"/subscriptions/{sub}/providers/Microsoft.KeyVault/vaults",
                    "2023-07-01",
                ):
                    props = raw.get("properties", {})
                    snap["key_vaults"].append(
                        {
                            "id": raw.get("id", ""),
                            "name": raw.get("name", ""),
                            "location": raw.get("location", "global"),
                            "tags": raw.get("tags") or {},
                            "enable_rbac_authorization": bool(
                                props.get("enableRbacAuthorization", False)
                            ),
                            "enable_purge_protection": bool(
                                props.get("enablePurgeProtection", False)
                            ),
                            "public_network_access": props.get("publicNetworkAccess", "Enabled"),
                        }
                    )
            except Exception as exc:
                partial_failures.append(
                    {"service": "Microsoft.KeyVault", "error": type(exc).__name__}
                )

            # 6. RBAC Role Assignments
            try:
                for raw in self._arm_get_paginated(
                    client,
                    token,
                    f"/subscriptions/{sub}/providers/Microsoft.Authorization/roleAssignments",
                    "2022-04-01",
                ):
                    props = raw.get("properties", {})
                    role_def_id = str(props.get("roleDefinitionId", "")).rsplit("/", 1)[-1].lower()
                    snap["role_assignments"].append(
                        {
                            "principal_id": props.get("principalId", "unknown"),
                            "principal_type": props.get("principalType", "Unknown"),
                            "role_name": _BUILTIN_ROLE_NAMES.get(role_def_id, role_def_id),
                            "scope": props.get("scope", ""),
                        }
                    )
            except Exception as exc:
                partial_failures.append(
                    {"service": "Microsoft.Authorization", "error": type(exc).__name__}
                )

            # 7. Subscription Activity Log Diagnostic Settings
            try:
                diag_items = self._arm_get_paginated(
                    client,
                    token,
                    f"/subscriptions/{sub}/providers/Microsoft.Insights/diagnosticSettings",
                    "2021-05-01-preview",
                )
                snap["diagnostic_settings"] = {"activity_log_exported": bool(diag_items)}
            except Exception as exc:
                partial_failures.append(
                    {"service": "Microsoft.Insights", "error": type(exc).__name__}
                )

            # 8. Microsoft Defender for Cloud Pricings
            try:
                pricings = self._arm_get_paginated(
                    client,
                    token,
                    f"/subscriptions/{sub}/providers/Microsoft.Security/pricings",
                    "2024-01-01",
                )
                standard_on = any(
                    str(p.get("properties", {}).get("pricingTier", "")).lower() == "standard"
                    for p in pricings
                )
                snap["defender_for_cloud"] = {"standard_tier_enabled": standard_on}
            except Exception as exc:
                partial_failures.append(
                    {"service": "Microsoft.Security", "error": type(exc).__name__}
                )
        finally:
            if own_client:
                client.close()

        return snap, partial_failures

    def validate_connection(self) -> PreflightResult:
        errors = self._validate_scope_and_auth_mode()
        if errors:
            return PreflightResult(
                valid=False,
                provider="azure",
                account_or_subscription_id=self.subscription_id,
                identity_arn_or_principal=self.azure_client_id or self.auth_mode,
                auth_mode=self.auth_mode,
                data_source=self.data_source,
                checked_permissions={"Microsoft.Resources/subscriptions/read": "denied"},
                errors=errors,
            )

        if self.data_source == "synthetic_fixture":
            snap = self._fixture_snapshot or get_synthetic_azure_snapshot(self.subscription_id)
            return PreflightResult(
                valid=True,
                provider="azure",
                account_or_subscription_id=self.subscription_id,
                identity_arn_or_principal=str(snap["principal"]),
                auth_mode=self.auth_mode,
                data_source="synthetic_fixture",
                checked_permissions={
                    "Microsoft.Resources/subscriptions/read": "ok",
                    "Microsoft.Storage/storageAccounts/read": "ok",
                    "Microsoft.Network/networkSecurityGroups/read": "ok",
                    "Microsoft.Authorization/roleAssignments/read": "ok",
                    "Microsoft.KeyVault/vaults/read": "ok",
                },
                errors=[],
            )

        try:
            token = self._acquire_arm_token()
            sub_url = validate_outbound_https_url(
                f"{_ARM_BASE_URL}/subscriptions/{self.subscription_id}?api-version=2022-12-01"
            )
            own_client = self._http_client is None
            client = self._http_client or httpx.Client(timeout=15.0)
            try:
                resp = client.get(
                    sub_url,
                    headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                    timeout=15.0,
                )
                if resp.status_code in (401, 403, 404):
                    return PreflightResult(
                        valid=False,
                        provider="azure",
                        account_or_subscription_id=self.subscription_id,
                        identity_arn_or_principal=self.azure_client_id or self.auth_mode,
                        auth_mode=self.auth_mode,
                        data_source="live",
                        checked_permissions={
                            "arm_token": "ok",
                            "Microsoft.Resources/subscriptions/read": "denied",
                        },
                        errors=[
                            f"Azure subscription preflight check failed with HTTP {resp.status_code}."
                        ],
                    )
                resp.raise_for_status()
            finally:
                if own_client:
                    client.close()

            return PreflightResult(
                valid=True,
                provider="azure",
                account_or_subscription_id=self.subscription_id,
                identity_arn_or_principal=self.azure_client_id or self.auth_mode,
                auth_mode=self.auth_mode,
                data_source="live",
                checked_permissions={
                    "arm_token": "ok",
                    "Microsoft.Resources/subscriptions/read": "ok",
                },
                errors=[],
            )
        except Exception as exc:
            return PreflightResult(
                valid=False,
                provider="azure",
                account_or_subscription_id=self.subscription_id,
                identity_arn_or_principal=self.azure_client_id or self.auth_mode,
                auth_mode=self.auth_mode,
                data_source="live",
                checked_permissions={"arm_token": "denied"},
                errors=[f"Azure Identity/ARM preflight failed ({type(exc).__name__})"],
            )

    def collect_and_assess(self) -> CollectionReport:
        partial_failures: list[dict[str, Any]] = []
        if self.data_source == "synthetic_fixture":
            snap = self._fixture_snapshot or get_synthetic_azure_snapshot(self.subscription_id)
        else:
            try:
                snap, partial_failures = self._collect_live_snapshot()
            except Exception as exc:
                return CollectionReport(
                    assets=[],
                    evaluations=[],
                    partial_failures=[{"service": "azure_identity", "error": type(exc).__name__}],
                    data_source="live",
                )

        assets: list[DiscoveredAsset] = []
        evaluations: list[CheckEvaluation] = []

        for stg in snap.get("storage_accounts", []):
            assets.append(
                DiscoveredAsset(
                    provider="azure",
                    account_ref=self.subscription_id,
                    resource_id=str(stg["id"]),
                    resource_name=str(stg["name"]),
                    resource_type="azure_storage_account",
                    region=str(stg.get("location", "eastus")),
                    tags=dict(stg.get("tags", {})),
                    configuration={
                        "allow_blob_public_access": stg.get("allow_blob_public_access"),
                        "supports_https_traffic_only": stg.get("supports_https_traffic_only"),
                        "minimum_tls_version": stg.get("minimum_tls_version"),
                    },
                    data_source=self.data_source,
                )
            )
            evaluations.extend(
                evaluate_azure_storage_account(
                    subscription_id=self.subscription_id,
                    account=stg,
                    data_source=self.data_source,
                )
            )

        for vm in snap.get("virtual_machines", []):
            assets.append(
                DiscoveredAsset(
                    provider="azure",
                    account_ref=self.subscription_id,
                    resource_id=str(vm["id"]),
                    resource_name=str(vm["name"]),
                    resource_type="azure_virtual_machine",
                    region=str(vm.get("location", "eastus")),
                    tags=dict(vm.get("tags", {})),
                    configuration={"vm_size": vm.get("vm_size")},
                    data_source=self.data_source,
                )
            )

        for nsg in snap.get("nsgs", []):
            assets.append(
                DiscoveredAsset(
                    provider="azure",
                    account_ref=self.subscription_id,
                    resource_id=str(nsg["id"]),
                    resource_name=str(nsg["name"]),
                    resource_type="azure_nsg",
                    region=str(nsg.get("location", "eastus")),
                    tags=dict(nsg.get("tags", {})),
                    configuration={"security_rules": nsg.get("security_rules", [])},
                    data_source=self.data_source,
                )
            )
            evaluations.append(
                evaluate_azure_nsg(
                    subscription_id=self.subscription_id,
                    nsg=nsg,
                    data_source=self.data_source,
                )
            )

        for vnet in snap.get("vnets", []):
            assets.append(
                DiscoveredAsset(
                    provider="azure",
                    account_ref=self.subscription_id,
                    resource_id=str(vnet["id"]),
                    resource_name=str(vnet["name"]),
                    resource_type="azure_vnet",
                    region=str(vnet.get("location", "eastus")),
                    tags=dict(vnet.get("tags", {})),
                    configuration={"address_space": vnet.get("address_space", [])},
                    data_source=self.data_source,
                )
            )

        for kv in snap.get("key_vaults", []):
            assets.append(
                DiscoveredAsset(
                    provider="azure",
                    account_ref=self.subscription_id,
                    resource_id=str(kv["id"]),
                    resource_name=str(kv["name"]),
                    resource_type="azure_key_vault",
                    region=str(kv.get("location", "eastus")),
                    tags=dict(kv.get("tags", {})),
                    configuration={
                        "enable_rbac_authorization": kv.get("enable_rbac_authorization"),
                        "enable_purge_protection": kv.get("enable_purge_protection"),
                        "public_network_access": kv.get("public_network_access"),
                    },
                    data_source=self.data_source,
                )
            )
            evaluations.append(
                evaluate_azure_key_vault(
                    subscription_id=self.subscription_id,
                    vault=kv,
                    data_source=self.data_source,
                )
            )

        evaluations.append(
            evaluate_azure_rbac(
                subscription_id=self.subscription_id,
                assignments=list(snap.get("role_assignments", [])),
                data_source=self.data_source,
            )
        )
        evaluations.extend(
            evaluate_azure_diagnostics_and_monitoring(
                subscription_id=self.subscription_id,
                diagnostics=dict(snap.get("diagnostic_settings", {})),
                defender=dict(snap.get("defender_for_cloud", {})),
                data_source=self.data_source,
            )
        )

        # Emit explicit NOT_ASSESSED / ERROR CheckEvaluations for failed ARM provider calls
        failed_services = {
            str(pf.get("service")): str(pf.get("error", "Unknown")) for pf in partial_failures
        }
        for svc_key, rule_id, r_type, r_title, r_perm in (
            (
                "Microsoft.Storage",
                "AZ-STG-001",
                "azure_storage_account",
                "Azure Storage account public access assessment",
                "Microsoft.Storage/storageAccounts/read",
            ),
            (
                "Microsoft.Network/nsg",
                "AZ-NET-001",
                "azure_nsg",
                "Azure NSG inbound port assessment",
                "Microsoft.Network/networkSecurityGroups/read",
            ),
            (
                "Microsoft.KeyVault",
                "AZ-KV-001",
                "azure_key_vault",
                "Azure Key Vault hardening assessment",
                "Microsoft.KeyVault/vaults/read",
            ),
            (
                "Microsoft.Authorization",
                "AZ-IAM-001",
                "azure_rbac_scope",
                "Subscription-wide Owner/User Access Administrator assignments must be minimized",
                "Microsoft.Authorization/roleAssignments/read",
            ),
            (
                "Microsoft.Insights",
                "AZ-MON-001",
                "azure_diagnostic_settings",
                "Azure subscription must export Activity Logs via Diagnostic Settings",
                "Microsoft.Insights/diagnosticSettings/read",
            ),
            (
                "Microsoft.Security",
                "AZ-MON-002",
                "azure_defender_for_cloud",
                "Microsoft Defender for Cloud monitoring must be enabled",
                "Microsoft.Security/pricings/read",
            ),
        ):
            if svc_key in failed_services:
                err_name = failed_services[svc_key]
                if rule_id in ("AZ-IAM-001", "AZ-MON-001", "AZ-MON-002"):
                    evaluations = [ev for ev in evaluations if ev.rule_id != rule_id]
                is_perm = "Permission" in err_name or "403" in err_name
                evaluations.append(
                    CheckEvaluation(
                        rule_id=rule_id,
                        rule_version="1.0.0",
                        provider="azure",
                        account_ref=self.subscription_id,
                        resource_id=f"/subscriptions/{self.subscription_id}/providers/{svc_key}",
                        resource_type=r_type,
                        region="global",
                        title=r_title,
                        description=f"ARM collection failed for {svc_key}: {err_name}",
                        status=CheckStatus.NOT_ASSESSED if is_perm else CheckStatus.ERROR,
                        severity=Severity.HIGH,
                        confidence=Confidence.LOW,
                        required_permissions=[r_perm],
                        expected_config={"collection_succeeded": True},
                        observed_config={"service": svc_key, "error": err_name},
                        evidence={"service": svc_key, "error": err_name},
                        explanation=f"Unable to evaluate {rule_id} because {svc_key} API failed ({err_name}).",
                        remediation_guidance=f"Grant {r_perm} Reader access on the target subscription.",
                        framework_mappings=[],
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
            snap = self._fixture_snapshot or get_synthetic_azure_snapshot(self.subscription_id)
        else:
            try:
                snap, partial = self._collect_live_snapshot()
                for pf in partial:
                    if pf.get("service") == "Microsoft.Authorization":
                        extra_limitations.append(
                            f"Live Azure RBAC collection encountered partial error: {pf.get('error')}."
                        )
            except Exception as exc:
                snap = {"role_assignments": []}
                extra_limitations.append(
                    f"Live Azure identity collection failed ({type(exc).__name__}); 0 principals could be evaluated."
                )

        items: list[IdentityRiskItem] = []
        assignments = snap.get("role_assignments", [])
        for assignment in assignments:
            role_name = str(assignment.get("role_name", ""))
            if role_name in ("Owner", "User Access Administrator"):
                items.append(
                    IdentityRiskItem(
                        provider="azure",
                        account_ref=self.subscription_id,
                        principal_id=str(assignment["principal_id"]),
                        principal_type=str(assignment.get("principal_type", "Unknown")),
                        risk_category="privileged_rbac_assignment",
                        severity=Severity.HIGH,
                        evidence=assignment,
                        recommendation="Scope RBAC role to resource group level and enable Entra PIM just-in-time activation.",
                    )
                )
            if assignment.get("principal_type") == "ServicePrincipal" and role_name == "Owner":
                items.append(
                    IdentityRiskItem(
                        provider="azure",
                        account_ref=self.subscription_id,
                        principal_id=str(assignment["principal_id"]),
                        principal_type="ServicePrincipal",
                        risk_category="service_principal_overprivileged",
                        severity=Severity.CRITICAL,
                        evidence=assignment,
                        recommendation="Remove Owner from Service Principal; replace with narrow custom RBAC role and Workload Identity Federation.",
                    )
                )

        return IdentityAnalysisReport(
            provider="azure",
            account_ref=self.subscription_id,
            data_source=self.data_source,
            principals_reviewed=len(assignments),
            findings=items,
            limitations=extra_limitations
            + [
                "Entra ID MFA registration and inactive user sign-in dates require optional Microsoft Graph AuditLog.Read.All and UserAuthenticationMethod.Read.All permissions.",
                "Conditional Access policy interactions and nested Entra group memberships are not fully resolved from ARM roleAssignments alone.",
            ],
        )
