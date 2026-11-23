# Cloud Lab Validation Tests

**Status**: Policy & Sandbox Templates Ready (`infrastructure/terraform/{aws,azure}/`) — **Manual Execution Only**

These tests are reserved for live validation against isolated, human-provisioned AWS and Azure sandbox accounts using short-lived read-only credentials (`pytest -m cloud_lab`).

## Mandatory Safeguards
1. **Never executed in public GitHub Actions** (`ci.yml` explicitly runs `pytest -v -m "not cloud_lab"`).
2. Provision isolated test resources strictly via `infrastructure/terraform/aws/` or `infrastructure/terraform/azure/` with explicit human approval.
3. Destroy all sandbox resources immediately after validation per `CLEANUP_AND_BUDGET.md` and confirm zero remaining `ManagedBy=CloudSentinelLab` resources.
