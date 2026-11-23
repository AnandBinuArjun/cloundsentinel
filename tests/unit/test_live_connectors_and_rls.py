"""Unit tests verifying live Azure ARM collector pagination, OIDC JWKS SSRF guard, and RLS migration."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

import httpx
import pytest

from cloud_connectors.azure.connector import AzureConnector
from packages.assessment.interface import CheckStatus
from packages.auth.oidc import OIDCVerifier
from packages.common.config import Settings

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.unit
def test_azure_live_arm_collector_paginates_and_evaluates_real_arm_responses() -> None:
    sub_id = "00000000-1111-2222-3333-444444444444"

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "storageAccounts" in path:
            if "page=2" not in str(request.url):
                return httpx.Response(
                    200,
                    json={
                        "value": [
                            {
                                "id": f"/subscriptions/{sub_id}/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/stopen1",
                                "name": "stopen1",
                                "location": "eastus",
                                "properties": {
                                    "allowBlobPublicAccess": True,
                                    "supportsHttpsTrafficOnly": False,
                                    "minimumTlsVersion": "TLS1_0",
                                    "encryption": {"requireInfrastructureEncryption": False},
                                },
                            }
                        ],
                        "nextLink": f"https://management.azure.com{path}?api-version=2023-05-01&page=2",
                    },
                )
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "id": f"/subscriptions/{sub_id}/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/stsecure2",
                            "name": "stsecure2",
                            "location": "eastus",
                            "properties": {
                                "allowBlobPublicAccess": False,
                                "supportsHttpsTrafficOnly": True,
                                "minimumTlsVersion": "TLS1_2",
                                "encryption": {
                                    "services": {"blob": {"enabled": True}},
                                    "requireInfrastructureEncryption": True,
                                },
                            },
                        }
                    ]
                },
            )
        if "networkSecurityGroups" in path:
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "id": f"/subscriptions/{sub_id}/resourceGroups/rg1/providers/Microsoft.Network/networkSecurityGroups/nsg1",
                            "name": "nsg1",
                            "location": "eastus",
                            "properties": {
                                "securityRules": [
                                    {
                                        "name": "OpenSSH",
                                        "properties": {
                                            "direction": "Inbound",
                                            "access": "Allow",
                                            "sourceAddressPrefix": "Internet",
                                            "destinationPortRange": "22",
                                        },
                                    }
                                ]
                            },
                        }
                    ]
                },
            )
        if "roleAssignments" in path:
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "properties": {
                                "principalId": "sp-1",
                                "principalType": "ServicePrincipal",
                                "roleDefinitionId": "/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
                                "scope": f"/subscriptions/{sub_id}",
                            }
                        }
                    ]
                },
            )
        return httpx.Response(200, json={"value": []})

    mock_client = httpx.Client(transport=httpx.MockTransport(handler))
    connector = AzureConnector(
        subscription_id=sub_id,
        auth_mode="managed_identity",
        data_source="live",
        http_client=mock_client,
    )
    with patch.object(AzureConnector, "_acquire_arm_token", return_value="fake-arm-token"):
        report = connector.collect_and_assess()

    assert report.data_source == "live"
    assert report.partial_failures == []
    # Both paginated storage accounts + NSG discovered
    storage_assets = [a for a in report.assets if a.resource_type == "azure_storage_account"]
    assert len(storage_assets) == 2
    assert any(
        ev.rule_id == "AZ-STG-001" and ev.status == CheckStatus.FAIL for ev in report.evaluations
    )
    assert any(
        ev.rule_id == "AZ-STG-001" and ev.status == CheckStatus.PASS for ev in report.evaluations
    )
    assert any(
        ev.rule_id == "AZ-NET-001" and ev.status == CheckStatus.FAIL for ev in report.evaluations
    )
    mock_client.close()


@pytest.mark.unit
def test_oidc_verifier_rejects_ssrf_jwks_url() -> None:
    bad_settings = Settings(
        CLOUDSENTINEL_ENV="production",
        OIDC_JWKS_URL="http://169.254.169.254/latest/meta-data/",
    )
    with pytest.raises(ValueError):
        OIDCVerifier(bad_settings)


@pytest.mark.unit
def test_rls_migration_and_opa_tests_present() -> None:
    rls_file = REPO_ROOT / "database" / "migrations" / "versions" / "0002_postgres_rls_policies.py"
    text = rls_file.read_text(encoding="utf-8")
    assert "ENABLE ROW LEVEL SECURITY" in text
    assert "app.current_tenant_id" in text
    assert 'down_revision = "0001_initial_schema"' in text

    opa_test = REPO_ROOT / "policies" / "opa" / "policies_test.rego"
    assert opa_test.exists() and "test_deny_public_s3_block_disabled" in opa_test.read_text(
        encoding="utf-8"
    )


@pytest.mark.unit
def test_prowler_workflow_is_manual_dispatch_only() -> None:
    import yaml

    wf: dict[str, Any] = yaml.safe_load(
        (REPO_ROOT / ".github" / "workflows" / "cloud-lab-prowler.yml").read_text(encoding="utf-8")
    )
    # PyYAML parses bare `on:` as boolean True or "on"
    triggers = wf.get("on", wf.get(True))
    assert isinstance(triggers, dict)
    assert list(triggers.keys()) == ["workflow_dispatch"]
