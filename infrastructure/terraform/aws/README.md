# AWS Security Lab Infrastructure (Terraform)

**Status**: Templates Implemented v1.0.0 (`Milestone 9`) — **Not Applied Automatically**

## Files
- `main.tf` — Provisions a sandbox read-only IAM role (`CloudSentinelReadOnlyRole` with `ExternalId` trust condition + `SecurityAudit`) and a baseline encrypted, non-public S3 bucket tagged `ManagedBy=CloudSentinelLab`.
- `variables.tf` — Input variables (`aws_region`, `lab_prefix`, `unique_suffix`, `trusted_principal_arn`, sensitive `external_id`).
- `CLEANUP_AND_BUDGET.md` — Mandatory cost alerts (< \$1/mo free-tier estimate) and `terraform destroy` cleanup verification guide.

> **Safety Notice**: Deploy strictly into an isolated sandbox AWS account with explicit human approval — never into production.
