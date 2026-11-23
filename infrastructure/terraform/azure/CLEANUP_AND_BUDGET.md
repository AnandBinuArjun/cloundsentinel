# Azure Isolated Security Lab — Budget & Cleanup Guide

> **WARNING**: Deploy strictly into a dedicated sandbox Azure subscription with an Azure Cost Management budget alert (USD 5.00 cap).

## Estimated Monthly Cost
- Resource Group + Standard LRS Storage Account (minimal test objects): **less than USD 1.00/month**.

## Mandatory Cleanup Procedure
After completing cloud-lab validation:
```bash
cd infrastructure/terraform/azure
terraform destroy -auto-approve
```
Verify the `cloudsentinel-lab-rg` resource group is completely deleted in Azure Portal or via `az group show`.
