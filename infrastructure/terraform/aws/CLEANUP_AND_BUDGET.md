# AWS Isolated Security Lab — Budget & Cleanup Guide

> **WARNING**: Never deploy this lab into a production AWS account. Run strictly in a dedicated sandbox account with AWS Budgets alerts enabled.

## Estimated Monthly Cost
- IAM Role + S3 Bucket (empty / test objects): **less than USD 1.00/month** (free-tier eligible).
- Set an AWS Budgets zero-spend / USD 5.00 alert before running `terraform apply`.

## Mandatory Cleanup Procedure
After completing cloud-lab validation tests:
```bash
cd infrastructure/terraform/aws
terraform destroy -auto-approve
```
Verify zero remaining `ManagedBy=CloudSentinelLab` resources using AWS Resource Groups Tag Editor.
