# Cloud Integration Standards (AWS & Azure)

1. **Common Provider Interface (`packages/assessment/interface.py`)**
   - Both `AWSConnector` (`cloud_connectors/aws/connector.py`) and `AzureConnector` (`cloud_connectors/azure/connector.py`) implement `CloudProviderConnector`.
   - Every security check returns one of four explicit `CheckStatus` values: `PASS`, `FAIL`, `NOT_ASSESSED`, or `ERROR`.
   - **Never interpret a failed API call, throttling error, or missing permission as `PASS`.**

2. **AWS Requirements (`cloud_connectors/aws/`)**
   - Authenticate via cross-account IAM role assumption using AWS STS (`AssumeRole`) with `ExternalId` and short-lived 15-minute session credentials (`DurationSeconds=900`).
   - Follow the least-privilege policy in `cloud_connectors/aws/permissions.json`; reject `:root` ARNs and root credentials.
   - Support account ID verification, region selection, permission preflight, pagination, retries with backoff, and partial-failure reporting.

3. **Azure Requirements (`cloud_connectors/azure/`)**
   - Prioritize `managed_identity` and `workload_identity`, allowing `service_principal_secret_ref` only with an external secret manager binding (never raw secrets in database columns).
   - Follow the least-privilege custom Reader role in `cloud_connectors/azure/permissions.json`; never require Global Administrator privileges.
   - Support subscription UUID validation, permission preflight, and explicit Entra ID / Microsoft Graph analysis limitations.

4. **Evidence & Provenance**
   - Every finding must attach reproducible redacted evidence (`rule_id`, `rule_version`, `provider`, `account_ref`, `resource_id`, `expected_config`, `observed_config`, collection timestamp, `data_source`, and `limitations`).
