# AWS Cloud Connector

**Status**: Implemented v1.0.0 (`Milestone 2`)

## Capabilities
- **Authentication (`connector.py`)**: Cross-account IAM role assumption via AWS STS (`AssumeRole`, `DurationSeconds=900`) with `ExternalId`, account ID verification via `GetCallerIdentity`, and explicit rejection of `:root` ARNs.
- **Least-Privilege Manifest (`permissions.json`)**: Version-controlled read-only IAM policy covering STS, S3, EC2/EBS, IAM, CloudTrail, Security Hub, and GuardDuty.
- **Deterministic Security Rules (`rules.py`)**: 10 rules (`AWS-S3-001..003`, `AWS-EC2-001..002`, `AWS-CT-001`, `AWS-IAM-001..002`, `AWS-EBS-001`, `AWS-MON-001`) returning `PASS`, `FAIL`, `NOT_ASSESSED`, or `ERROR` with expected vs. observed evidence.
- **Identity Analysis (`analyze_identities`)**: Flags console users without MFA, direct admin IAM users, and wildcard cross-account trust policies, while explicitly reporting SCP/permission-boundary limitations.
- **Synthetic Fixtures (`fixtures.py`)**: Deterministic `data_source="synthetic_fixture"` snapshot for CI and local testing (never presented as live cloud data).
