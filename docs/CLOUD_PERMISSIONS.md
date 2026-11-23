# Cloud Permissions & Least-Privilege Manifests

**Status**: Implemented v1.0.0 — Enforced in `cloud_connectors/aws/` & `cloud_connectors/azure/`

---

## 1. AWS Assessment Permissions (Read-Only Default)

- **Version-controlled IAM policy**: [`cloud_connectors/aws/permissions.json`](../cloud_connectors/aws/permissions.json)
- **Terraform lab role template**: [`infrastructure/terraform/aws/main.tf`](../infrastructure/terraform/aws/main.tf)
- **Authentication**: Cross-account IAM Role assumption using AWS STS (`sts:AssumeRole`) with tenant-specific `ExternalId` and short-lived 15-minute session credentials (`DurationSeconds=900`).

**Explicitly Prohibited & Rejected in Code**:
- AWS Root Account credentials or `:root` ARNs (rejected by both `ConnectionCreateRequest` and `AWSConnector._validate_role_arn_safety()`).
- Long-lived IAM user keys stored in source code or database columns.
- Mutating IAM actions on the assessment role.

### Scoped Read-Only Actions Included in `cloud_connectors/aws/permissions.json`
- **Identity & Preflight**: `sts:GetCallerIdentity`
- **S3**: `s3:ListAllMyBuckets`, `s3:GetBucketPublicAccessBlock`, `s3:GetBucketPolicy`, `s3:GetBucketPolicyStatus`, `s3:GetBucketAcl`, `s3:GetEncryptionConfiguration`, `s3:GetBucketLocation`
- **EC2 / EBS / Security Groups**: `ec2:DescribeRegions`, `ec2:DescribeInstances`, `ec2:DescribeSecurityGroups`, `ec2:DescribeVolumes`, `ec2:GetEbsEncryptionByDefault`
- **IAM**: `iam:GetAccountSummary`, `iam:GetAccountPasswordPolicy`, `iam:ListUsers`, `iam:ListRoles`, `iam:ListPolicies`, `iam:GetPolicyVersion`, `iam:ListAttachedUserPolicies`, `iam:ListAttachedRolePolicies`, `iam:ListMFADevices`, `iam:ListAccessKeys`
- **CloudTrail & Monitoring**: `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`, `cloudtrail:GetEventSelectors`, `cloudtrail:LookupEvents`, `securityhub:DescribeHub`, `guardduty:ListDetectors`

> **Remediation Separation**: Live remediation is disabled by default (`CLOUDSENTINEL_LIVE_REMEDIATION_ENABLED=false`) and requires a dedicated, separate `CLOUDSENTINEL_REMEDIATION_AWS_ROLE_ARN`.

---

## 2. Microsoft Azure Assessment Permissions (Read-Only Default)

- **Version-controlled Custom Reader Role**: [`cloud_connectors/azure/permissions.json`](../cloud_connectors/azure/permissions.json)
- **Terraform lab template**: [`infrastructure/terraform/azure/main.tf`](../infrastructure/terraform/azure/main.tf)
- **Authentication**: Prioritizes `managed_identity` and `workload_identity`, with `service_principal_secret_ref` requiring an external secret manager binding (never raw secrets in database columns).

**Explicitly Prohibited**:
- Microsoft Entra **Global Administrator** privileges for routine posture checks.
- Standing `Owner` or `Contributor` assignments for read-only discovery.

### Scoped Read-Only ARM Actions Included in `cloud_connectors/azure/permissions.json`
- `Microsoft.Resources/subscriptions/read`
- `Microsoft.Compute/virtualMachines/read`
- `Microsoft.Storage/storageAccounts/read` & `blobServices/containers/read`
- `Microsoft.Network/networkSecurityGroups/read` & `virtualNetworks/read`
- `Microsoft.Authorization/roleAssignments/read` & `roleDefinitions/read`
- `Microsoft.KeyVault/vaults/read`
- `Microsoft.Insights/diagnosticSettings/read`
- `Microsoft.Security/pricings/read` & `assessments/read`

> **Entra ID Graph Limitations**: Optional Microsoft Graph permissions (`AuditLog.Read.All`, `UserAuthenticationMethod.Read.All`) are not required for ARM assessment; `AzureConnector.analyze_identities()` explicitly surfaces those limitations on every report.
