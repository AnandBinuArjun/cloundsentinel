"""Explicitly labeled synthetic Microsoft Azure subscription fixtures for CI and local demos."""

from __future__ import annotations

from typing import Any


def get_synthetic_azure_snapshot(
    subscription_id: str = "00000000-1111-2222-3333-444444444444",
) -> dict[str, Any]:
    """Return a deterministic synthetic Azure subscription snapshot (NEVER live cloud data)."""
    return {
        "subscription_id": subscription_id,
        "principal": "managed-identity://cloudsentinel-reader-mi",
        "storage_accounts": [
            {
                "id": f"/subscriptions/{subscription_id}/resourceGroups/rg-prod-data/providers/Microsoft.Storage/storageAccounts/stacmelegacy01",
                "name": "stacmelegacy01",
                "location": "eastus",
                "tags": {"Environment": "prod"},
                "allow_blob_public_access": True,
                "supports_https_traffic_only": False,
                "minimum_tls_version": "TLS1_0",
                "encryption_enabled": True,
                "require_infrastructure_encryption": False,
            },
            {
                "id": f"/subscriptions/{subscription_id}/resourceGroups/rg-prod-sec/providers/Microsoft.Storage/storageAccounts/stacmesecure02",
                "name": "stacmesecure02",
                "location": "eastus",
                "tags": {"Environment": "prod"},
                "allow_blob_public_access": False,
                "supports_https_traffic_only": True,
                "minimum_tls_version": "TLS1_2",
                "encryption_enabled": True,
                "require_infrastructure_encryption": True,
            },
        ],
        "virtual_machines": [
            {
                "id": f"/subscriptions/{subscription_id}/resourceGroups/rg-prod-app/providers/Microsoft.Compute/virtualMachines/vm-app-01",
                "name": "vm-app-01",
                "location": "eastus",
                "tags": {"Environment": "prod"},
                "vm_size": "Standard_D2s_v5",
            }
        ],
        "nsgs": [
            {
                "id": f"/subscriptions/{subscription_id}/resourceGroups/rg-prod-net/providers/Microsoft.Network/networkSecurityGroups/nsg-edge-open",
                "name": "nsg-edge-open",
                "location": "eastus",
                "tags": {"Environment": "prod"},
                "security_rules": [
                    {
                        "name": "AllowSSHFromInternet",
                        "direction": "Inbound",
                        "access": "Allow",
                        "source_address_prefix": "Internet",
                        "destination_port_range": "22",
                    }
                ],
            }
        ],
        "vnets": [
            {
                "id": f"/subscriptions/{subscription_id}/resourceGroups/rg-prod-net/providers/Microsoft.Network/virtualNetworks/vnet-prod-eastus",
                "name": "vnet-prod-eastus",
                "location": "eastus",
                "address_space": ["10.20.0.0/16"],
                "tags": {"Environment": "prod"},
            }
        ],
        "key_vaults": [
            {
                "id": f"/subscriptions/{subscription_id}/resourceGroups/rg-prod-sec/providers/Microsoft.KeyVault/vaults/kv-acme-legacy",
                "name": "kv-acme-legacy",
                "location": "eastus",
                "tags": {"Environment": "prod"},
                "enable_rbac_authorization": False,
                "enable_purge_protection": False,
                "public_network_access": "Enabled",
            }
        ],
        "role_assignments": [
            {
                "principal_id": "sp-automation-owner-01",
                "principal_type": "ServicePrincipal",
                "role_name": "Owner",
                "scope": f"/subscriptions/{subscription_id}",
            },
            {
                "principal_id": "user-admin-01",
                "principal_type": "User",
                "role_name": "Owner",
                "scope": f"/subscriptions/{subscription_id}",
            },
            {
                "principal_id": "user-admin-02",
                "principal_type": "User",
                "role_name": "User Access Administrator",
                "scope": f"/subscriptions/{subscription_id}",
            },
        ],
        "diagnostic_settings": {"activity_log_exported": False},
        "defender_for_cloud": {"standard_tier_enabled": False},
    }
