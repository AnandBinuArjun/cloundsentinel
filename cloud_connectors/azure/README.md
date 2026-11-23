# Microsoft Azure Cloud Connector

**Status**: Implemented v1.0.0 (`Milestone 3`)

## Capabilities
- **Authentication (`connector.py`)**: Supports `managed_identity` (`ManagedIdentityCredential`), `workload_identity` (`WorkloadIdentityCredential`), and controlled `service_principal_secret_ref` (external secret manager binding only — never raw secrets in DB columns). Validates subscription UUID scope and never requires Global Administrator.
- **Least-Privilege Manifest (`permissions.json`)**: Version-controlled custom read-only ARM role definition (`CloudSentinel Read-Only Security Assessor`).
- **Deterministic Security Rules (`rules.py`)**: 8 rules (`AZ-STG-001..003`, `AZ-NET-001`, `AZ-IAM-001`, `AZ-KV-001`, `AZ-MON-001..002`) covering Storage anonymous blob access, HTTPS/TLS 1.2+, encryption, NSG unrestricted inbound ports, subscription Owner RBAC sprawl, Key Vault hardening, Activity Log diagnostic settings, and Microsoft Defender for Cloud.
- **Identity Analysis (`analyze_identities`)**: Reviews subscription-wide Owner/User Access Administrator and overprivileged Service Principals while explicitly reporting Microsoft Graph / Entra PIM limitations.
- **Synthetic Fixtures (`fixtures.py`)**: Deterministic `data_source="synthetic_fixture"` snapshot for CI and local testing.
