# AWS Connector Validation & Evidence Integrity (Phase 5)

## 1. Connector Scope & Trust Boundary

- **Implementation**: `cloud_connectors/aws/connector.py` (`AWSConnector`) and `cloud_connectors/aws/rules.py`.
- **Authentication Model**: Short-lived AWS STS `AssumeRole` (`DurationSeconds=900`, `RoleSessionName="CloudSentinelReadOnlyAssessment"`) with optional `ExternalId` confused-deputy protection.
- **Root ARN Block**: `_validate_role_arn_safety()` explicitly rejects `:root` ARNs and verifies the 12-digit account ID in the role ARN matches `self.account_id`.

---

## 2. Hardened Capabilities (Phase 5)

1. **Per-Bucket Region Resolution**:
   - `_collect_live_snapshot()` queries `s3.get_bucket_location(Bucket=bname)` and normalizes `LocationConstraint` (`None`/`""` -> `us-east-1`, `"EU"` -> `eu-west-1`, regional code -> region) so S3 assets and findings record accurate regional metadata.
2. **Explicit `NOT_ASSESSED` / `ERROR` Evaluations on Service Failures**:
   - When top-level collection fails for `s3`, `ec2`, `cloudtrail`, or `iam`, `collect_and_assess()` emits explicit `CheckEvaluation` records with `CheckStatus.NOT_ASSESSED` (for `AccessDenied` / `UnauthorizedOperation`) or `CheckStatus.ERROR` (for transient/network errors) instead of silently omitting rules or falsely passing `AWS-CT-001`.
3. **Identity Analysis Error Transparency**:
   - `analyze_identities()` propagates collection failures and partial IAM errors into `IdentityAnalysisReport.limitations` rather than returning an unexplained empty report.
4. **Stale Finding Reconciliation & Latest-Run Compliance Scoping**:
   - `execute_queued_assessment_run()` reconciles open findings whose `(rule_id, resource_id)` no longer exist in a complete (`partial_failures == []`) assessment snapshot.
   - `/api/v1/compliance` scopes `AssessmentResult` aggregation to the latest completed/partial `AssessmentRun` per `connection_id`.

---

## 3. Validation Categories

| Validation Tier | Status | Evidence |
|---|---|---|
| Synthetic Fixture Assessment (`data_source="synthetic_fixture"`) | **VERIFIED** | `tests/unit/test_connectors_detections_compliance.py` |
| Mocked `boto3` ClientError / AccessDenied / Partial Failure | **VERIFIED** | `tests/security/test_hardening_phases_1_to_9.py` |
| Live AWS Account STS AssumeRole Sandbox | **NOT_RUN** | Requires owner-provided AWS sandbox credentials (`tests/cloud_lab/test_live_cloud_sandbox_policy.py`) |
