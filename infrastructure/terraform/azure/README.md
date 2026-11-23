# Azure Security Lab Infrastructure (Terraform)

**Status**: Templates Implemented v1.0.0 (`Milestone 9`) — **Not Applied Automatically**

## Files
- `main.tf` — Provisions an isolated sandbox Resource Group (`cloudsentinel-lab-rg`) and hardened Standard LRS Storage Account (`https_traffic_only_enabled=true`, `min_tls_version=TLS1_2`, `allow_nested_items_to_be_public=false`) tagged `ManagedBy=CloudSentinelLab`.
- `variables.tf` — Input variables (`azure_location`, `lab_prefix`, `storage_account_prefix`, `unique_suffix`).
- `CLEANUP_AND_BUDGET.md` — Mandatory Azure Cost Management budget guidance and `terraform destroy` cleanup verification steps.

> **Safety Notice**: Deploy strictly into an isolated sandbox Azure subscription with explicit human approval — never into production.
