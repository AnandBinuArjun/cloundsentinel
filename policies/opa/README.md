# Open Policy Agent (OPA) Policies

**Status**: Implemented v1.0.0 (`Milestone 9`)

## Included Rego Guardrails
- `aws_s3.rego` — Denies Terraform plans where `aws_s3_bucket_public_access_block` disables `block_public_acls` or `restrict_public_buckets` (`AWS-S3-001`).
- `azure_storage.rego` — Denies Terraform plans where `azurerm_storage_account` allows public blob access or sets `min_tls_version != "TLS1_2"` (`AZ-STG-001`, `AZ-STG-002`).
- `terraform_guardrails.rego` — Denies unrestricted `0.0.0.0/0` SSH ingress (`AWS-EC2-001`) and enforces mandatory `ManagedBy` resource ownership tags (`TAG-001`).
- `policies_test.rego` — OPA unit test suite executed in GitHub Actions CI (`opa test policies/opa -v`).
