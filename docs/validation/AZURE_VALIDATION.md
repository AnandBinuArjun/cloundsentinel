# Azure Connector Validation & Resilience (Phase 6)

## 1. Connector Scope & Trust Boundary

- **Implementation**: `cloud_connectors/azure/connector.py` (`AzureConnector`) and `cloud_connectors/azure/rules.py`.
- **Authentication Model**: Supports `managed_identity`, `workload_identity`, and controlled `service_principal_secret_ref` (raw secrets are never stored in database columns).
- **SSRF Protection**: Every outbound ARM URL and `nextLink` pagination URL is validated through `validate_outbound_https_url()` enforcing `https://management.azure.com`.

---

## 2. Hardened Capabilities (Phase 6)

1. **Subscription-Scoped Reader Preflight Verification**:
   - In live mode, `validate_connection()` acquires an ARM token AND executes `GET https://management.azure.com/subscriptions/{subscription_id}?api-version=2022-12-01` to verify `Microsoft.Resources/subscriptions/read` permission on the target subscription. HTTP `401`/`403`/`404` responses return `valid=False` with explicit error diagnostics.
2. **Bounded Retry/Backoff & Cyclic `nextLink` Guard**:
   - `_arm_get_paginated()` tracks `visited_urls: set[str]` to abort cyclic `nextLink` responses and implements bounded exponential backoff (`max_retries=3`, honoring `Retry-After`) for HTTP `429`, `502`, `503`, and `504`.
3. **Explicit `NOT_ASSESSED` / `ERROR` Evaluations on Provider Failures**:
   - When an ARM resource provider call (`Microsoft.Storage`, `Microsoft.Network/nsg`, `Microsoft.KeyVault`, `Microsoft.Authorization`, `Microsoft.Insights`, `Microsoft.Security`) fails, `collect_and_assess()` emits `CheckStatus.NOT_ASSESSED` (for permission errors) or `CheckStatus.ERROR` evaluations and replaces default `AZ-IAM-001` / `AZ-MON-001` / `AZ-MON-002` evaluations so failed ARM calls never appear as `PASS`.
4. **Identity Analysis Error Transparency**:
   - `analyze_identities()` records ARM collection failures in `IdentityAnalysisReport.limitations`.

---

## 3. Validation Categories

| Validation Tier | Status | Evidence |
|---|---|---|
| Synthetic Fixture Assessment (`data_source="synthetic_fixture"`) | **VERIFIED** | `tests/unit/test_connectors_detections_compliance.py` |
| Mocked ARM HTTP 403 / 429 Retry / Cyclic Pagination / Partial Failure | **VERIFIED** | `tests/security/test_hardening_phases_1_to_9.py` |
| Live Azure Subscription Workload Identity Sandbox | **NOT_RUN** | Requires owner-provided Azure sandbox credentials (`tests/cloud_lab/test_live_cloud_sandbox_policy.py`) |
