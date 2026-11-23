/**
 * Explicitly labeled synthetic demonstration fixture dataset (`data_source = "synthetic_fixture"`).
 *
 * Used ONLY when a visitor explicitly clicks "Sign In with Synthetic Demo Sandbox" on `/login`
 * (for example on a static Vercel preview deployment where no local FastAPI server is running).
 * Mirrors `database/seeds/seed_demo_fixtures.py` and preserves strict RBAC & Separation of Duties.
 */

import type {
  AssessmentRunItem,
  AssetItem,
  AuditEventItem,
  AuthIdentity,
  CloudConnectionItem,
  ComplianceResponse,
  DashboardSummary,
  DetectionItem,
  FindingDetailResponse,
  FindingItem,
  HealthResponse,
  IdentityAnalysisResponse,
  ReadinessResponse,
  RemediationItem,
  SystemInfoResponse,
} from "./api";

export const DEMO_ADMIN_TOKEN = "demo_synthetic_fixture_tenant_admin";
export const DEMO_ANALYST_TOKEN = "demo_synthetic_fixture_security_analyst";
const DEMO_TENANT_ID = "aea3b752-d682-4676-b6b9-52378d89426e";

export function isSyntheticDemoToken(token: string): boolean {
  return token === DEMO_ADMIN_TOKEN || token === DEMO_ANALYST_TOKEN;
}

export function getDemoIdentity(token: string): AuthIdentity {
  if (token === DEMO_ANALYST_TOKEN) {
    return {
      user_id: "753a9d79-8e8e-4f3d-8992-de1369737799",
      tenant_id: DEMO_TENANT_ID,
      email: "analyst@acme-demo.local",
      subject: "demo-security-analyst",
      role: "security_analyst",
      permissions: [
        "connections:read",
        "assets:read",
        "assessments:read",
        "assessments:run",
        "findings:read",
        "findings:write",
        "detections:read",
        "detections:write",
        "compliance:read",
        "reports:export",
        "remediations:preview",
      ],
    };
  }
  return {
    user_id: "b855519c-81bd-4d8a-8a2b-9b17aaa9da04",
    tenant_id: DEMO_TENANT_ID,
    email: "admin@acme-demo.local",
    subject: "demo-tenant-admin",
    role: "tenant_admin",
    permissions: [
      "connections:read",
      "connections:write",
      "assets:read",
      "assessments:read",
      "assessments:run",
      "findings:read",
      "findings:write",
      "detections:read",
      "detections:write",
      "compliance:read",
      "reports:export",
      "remediations:preview",
      "remediations:approve",
      "remediations:execute",
      "audit:read",
    ],
  };
}

let demoConnections: CloudConnectionItem[] = [
  {
    id: "conn-aws-demo-01",
    name: "AWS Production (Synthetic Fixture)",
    provider: "aws",
    auth_mode: "sts_assume_role",
    account_or_subscription_id: "123456789012",
    role_arn: "arn:aws:iam::123456789012:role/CloudSentinelReadOnlyRole",
    azure_tenant_id: null,
    regions: ["us-east-1", "us-west-2"],
    status: "healthy",
    data_source: "synthetic_fixture",
    preflight_summary: { sts_caller_identity: "verified", readonly_policy: "verified" },
    last_validated_at: "2026-11-23T15:00:00Z",
    created_at: "2026-11-23T14:00:00Z",
  },
  {
    id: "conn-az-demo-02",
    name: "Azure Prod Subscription (Synthetic Fixture)",
    provider: "azure",
    auth_mode: "managed_identity",
    account_or_subscription_id: "00000000-1111-2222-3333-444444444444",
    role_arn: null,
    azure_tenant_id: "88888888-4444-4444-4444-121212121212",
    regions: ["eastus", "westeurope"],
    status: "healthy",
    data_source: "synthetic_fixture",
    preflight_summary: { arm_reader_scope: "verified" },
    last_validated_at: "2026-11-23T15:00:00Z",
    created_at: "2026-11-23T14:00:00Z",
  },
];

const demoAssets: AssetItem[] = [
  {
    id: "asset-aws-s3-1",
    provider: "aws",
    account_ref: "123456789012",
    resource_id: "arn:aws:s3:::acme-prod-customer-exports",
    resource_name: "acme-prod-customer-exports",
    resource_type: "aws_s3_bucket",
    region: "us-east-1",
    tags: { Environment: "production", DataClassification: "confidential" },
    collection_status: "collected",
    data_source: "synthetic_fixture",
    last_observed_at: "2026-11-23T15:00:00Z",
  },
  {
    id: "asset-aws-sg-1",
    provider: "aws",
    account_ref: "123456789012",
    resource_id: "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0a1b2c3d4e",
    resource_name: "prod-bastion-sg",
    resource_type: "aws_security_group",
    region: "us-east-1",
    tags: { Environment: "production", Service: "bastion" },
    collection_status: "collected",
    data_source: "synthetic_fixture",
    last_observed_at: "2026-11-23T15:00:00Z",
  },
  {
    id: "asset-aws-iam-1",
    provider: "aws",
    account_ref: "123456789012",
    resource_id: "arn:aws:iam::123456789012:root",
    resource_name: "aws-account-root",
    resource_type: "aws_iam_root_account",
    region: "global",
    tags: { Tier: "control-plane" },
    collection_status: "collected",
    data_source: "synthetic_fixture",
    last_observed_at: "2026-11-23T15:00:00Z",
  },
  {
    id: "asset-aws-ct-1",
    provider: "aws",
    account_ref: "123456789012",
    resource_id: "arn:aws:cloudtrail:us-east-1:123456789012:trail/org-audit-trail",
    resource_name: "org-audit-trail",
    resource_type: "aws_cloudtrail_trail",
    region: "us-east-1",
    tags: { Compliance: "cis-aws" },
    collection_status: "collected",
    data_source: "synthetic_fixture",
    last_observed_at: "2026-11-23T15:00:00Z",
  },
  {
    id: "asset-aws-rds-1",
    provider: "aws",
    account_ref: "123456789012",
    resource_id: "arn:aws:rds:us-east-1:123456789012:db:acme-billing-db",
    resource_name: "acme-billing-db",
    resource_type: "aws_rds_instance",
    region: "us-east-1",
    tags: { Environment: "production", Engine: "postgres" },
    collection_status: "collected",
    data_source: "synthetic_fixture",
    last_observed_at: "2026-11-23T15:00:00Z",
  },
  {
    id: "asset-az-stg-1",
    provider: "azure",
    account_ref: "00000000-1111-2222-3333-444444444444",
    resource_id:
      "/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/acmestorageprod01",
    resource_name: "acmestorageprod01",
    resource_type: "azure_storage_account",
    region: "eastus",
    tags: { environment: "production", owner: "data-platform" },
    collection_status: "collected",
    data_source: "synthetic_fixture",
    last_observed_at: "2026-11-23T15:00:00Z",
  },
  {
    id: "asset-az-nsg-1",
    provider: "azure",
    account_ref: "00000000-1111-2222-3333-444444444444",
    resource_id:
      "/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/rg-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-prod-workload",
    resource_name: "nsg-prod-workload",
    resource_type: "azure_network_security_group",
    region: "eastus",
    tags: { environment: "production" },
    collection_status: "collected",
    data_source: "synthetic_fixture",
    last_observed_at: "2026-11-23T15:00:00Z",
  },
  {
    id: "asset-az-kv-1",
    provider: "azure",
    account_ref: "00000000-1111-2222-3333-444444444444",
    resource_id:
      "/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/rg-sec/providers/Microsoft.KeyVault/vaults/kv-acme-secrets",
    resource_name: "kv-acme-secrets",
    resource_type: "azure_key_vault",
    region: "eastus",
    tags: { criticality: "tier-0" },
    collection_status: "collected",
    data_source: "synthetic_fixture",
    last_observed_at: "2026-11-23T15:00:00Z",
  },
];

let demoFindings: FindingItem[] = [
  {
    id: "finding-aws-s3-001",
    rule_id: "AWS-S3-001",
    rule_version: "1.0.0",
    provider: "aws",
    account_ref: "123456789012",
    resource_id: "arn:aws:s3:::acme-prod-customer-exports",
    resource_type: "aws_s3_bucket",
    region: "us-east-1",
    title: "S3 bucket PublicAccessBlock is not fully enabled",
    description:
      "Amazon S3 Block Public Access settings (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets) are disabled on acme-prod-customer-exports.",
    severity: "critical",
    confidence: "high",
    status: "open",
    risk_score: 94,
    risk_explanation: {
      base_severity: 40,
      internet_exposure: 25,
      data_sensitivity: 19,
      privilege_impact: 10,
      formula: "min(100, severity + exposure + sensitivity + privilege)",
    },
    remediation_guidance:
      "Enable all four S3 PublicAccessBlock flags via aws s3api put-public-access-block.",
    framework_mappings: ["CIS-AWS-2.1.5", "NIST-CSF-PR.DS-01", "ISO27001-A.8.24"],
    limitations:
      "Evaluates bucket-level PublicAccessBlock configuration; does not inspect object-level ACLs individually.",
    data_source: "synthetic_fixture",
    first_seen_at: "2026-11-22T10:15:00Z",
    last_seen_at: "2026-11-23T15:00:00Z",
  },
  {
    id: "finding-aws-iam-001",
    rule_id: "AWS-IAM-001",
    rule_version: "1.0.0",
    provider: "aws",
    account_ref: "123456789012",
    resource_id: "arn:aws:iam::123456789012:root",
    resource_type: "aws_iam_root_account",
    region: "global",
    title: "AWS root account MFA is not enabled or root access keys exist",
    description:
      "The AWS account root user does not have hardware or virtual MFA enforced in account summary telemetry.",
    severity: "critical",
    confidence: "high",
    status: "open",
    risk_score: 96,
    risk_explanation: {
      base_severity: 40,
      internet_exposure: 20,
      data_sensitivity: 16,
      privilege_impact: 20,
    },
    remediation_guidance:
      "Enroll a FIDO2 hardware security key on the AWS root user and delete any active root access keys.",
    framework_mappings: ["CIS-AWS-1.5", "NIST-CSF-PR.AA-03", "ISO27001-A.8.5"],
    limitations: "Cannot verify physical custody of hardware MFA tokens via IAM API.",
    data_source: "synthetic_fixture",
    first_seen_at: "2026-11-21T09:00:00Z",
    last_seen_at: "2026-11-23T15:00:00Z",
  },
  {
    id: "finding-aws-ec2-001",
    rule_id: "AWS-EC2-001",
    rule_version: "1.0.0",
    provider: "aws",
    account_ref: "123456789012",
    resource_id: "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0a1b2c3d4e",
    resource_type: "aws_security_group",
    region: "us-east-1",
    title: "Security Group allows unrestricted SSH/RDP ingress from 0.0.0.0/0",
    description:
      "Security group prod-bastion-sg permits TCP port 22 from 0.0.0.0/0, exposing administrative management ports to the public internet.",
    severity: "high",
    confidence: "high",
    status: "open",
    risk_score: 84,
    risk_explanation: {
      base_severity: 30,
      internet_exposure: 25,
      data_sensitivity: 14,
      privilege_impact: 15,
    },
    remediation_guidance:
      "Revoke 0.0.0.0/0 ingress on TCP/22 and replace with AWS Systems Manager Session Manager or restricted VPN CIDRs.",
    framework_mappings: ["CIS-AWS-5.2", "NIST-CSF-PR.IR-01", "ISO27001-A.8.20"],
    limitations: "Does not evaluate upstream VPC Network ACLs or AWS Network Firewall rules.",
    data_source: "synthetic_fixture",
    first_seen_at: "2026-11-22T14:20:00Z",
    last_seen_at: "2026-11-23T15:00:00Z",
  },
  {
    id: "finding-az-stg-001",
    rule_id: "AZ-STG-001",
    rule_version: "1.0.0",
    provider: "azure",
    account_ref: "00000000-1111-2222-3333-444444444444",
    resource_id:
      "/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/acmestorageprod01",
    resource_type: "azure_storage_account",
    region: "eastus",
    title: "Azure Storage Account allows anonymous public blob access",
    description:
      "Storage account acmestorageprod01 has allowBlobPublicAccess=true and minimumTlsVersion=TLS1_0.",
    severity: "high",
    confidence: "high",
    status: "open",
    risk_score: 82,
    risk_explanation: {
      base_severity: 30,
      internet_exposure: 22,
      data_sensitivity: 18,
      privilege_impact: 12,
    },
    remediation_guidance:
      "Set allowBlobPublicAccess=false and minimumTlsVersion=TLS1_2 on the Azure Storage Account.",
    framework_mappings: ["CIS-AZURE-3.7", "NIST-CSF-PR.DS-01", "ISO27001-A.8.24"],
    limitations: "Evaluates ARM control-plane properties; does not scan blob contents.",
    data_source: "synthetic_fixture",
    first_seen_at: "2026-11-22T11:30:00Z",
    last_seen_at: "2026-11-23T15:00:00Z",
  },
  {
    id: "finding-az-nsg-001",
    rule_id: "AZ-NSG-001",
    rule_version: "1.0.0",
    provider: "azure",
    account_ref: "00000000-1111-2222-3333-444444444444",
    resource_id:
      "/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/rg-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-prod-workload",
    resource_type: "azure_network_security_group",
    region: "eastus",
    title: "Azure NSG permits inbound RDP (3389) from Any/Internet",
    description:
      "Network Security Group nsg-prod-workload contains an Allow inbound rule on port 3389 with sourceAddressPrefix='*'.",
    severity: "critical",
    confidence: "high",
    status: "open",
    risk_score: 90,
    risk_explanation: {
      base_severity: 40,
      internet_exposure: 25,
      data_sensitivity: 13,
      privilege_impact: 12,
    },
    remediation_guidance:
      "Remove wildcard inbound RDP rule and require Azure Bastion or Just-In-Time VM access.",
    framework_mappings: ["CIS-AZURE-6.1", "NIST-CSF-PR.IR-01", "ISO27001-A.8.20"],
    limitations: "Does not inspect Azure Firewall or Application Gateway upstream routing.",
    data_source: "synthetic_fixture",
    first_seen_at: "2026-11-22T12:00:00Z",
    last_seen_at: "2026-11-23T15:00:00Z",
  },
  {
    id: "finding-az-kv-001",
    rule_id: "AZ-KV-001",
    rule_version: "1.0.0",
    provider: "azure",
    account_ref: "00000000-1111-2222-3333-444444444444",
    resource_id:
      "/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/rg-sec/providers/Microsoft.KeyVault/vaults/kv-acme-secrets",
    resource_type: "azure_key_vault",
    region: "eastus",
    title: "Azure Key Vault purge protection or RBAC authorization is disabled",
    description:
      "Key Vault kv-acme-secrets has enablePurgeProtection=false, allowing permanent secret destruction during compromise.",
    severity: "medium",
    confidence: "high",
    status: "open",
    risk_score: 64,
    risk_explanation: {
      base_severity: 20,
      internet_exposure: 10,
      data_sensitivity: 20,
      privilege_impact: 14,
    },
    remediation_guidance:
      "Enable enablePurgeProtection=true and enableRbacAuthorization=true on Key Vault.",
    framework_mappings: ["CIS-AZURE-8.4", "NIST-CSF-PR.DS-01", "ISO27001-A.8.24"],
    limitations: "Read-only metadata inspection only; secret values are never accessed.",
    data_source: "synthetic_fixture",
    first_seen_at: "2026-11-22T16:10:00Z",
    last_seen_at: "2026-11-23T15:00:00Z",
  },
];

let demoDetections: DetectionItem[] = [
  {
    id: "det-aws-001",
    rule_id: "DET-AWS-001",
    provider: "aws",
    account_ref: "123456789012",
    region: "us-east-1",
    event_name: "StopLogging",
    actor_identity: "arn:aws:iam::123456789012:assumed-role/LegacyAdminRole/ops-session",
    source_ip: "198.51.100.42",
    severity: "critical",
    confidence: "high",
    mitre_tactic: "Defense Evasion",
    mitre_technique: "T1562.008",
    title: "AWS CloudTrail Audit Logging Stopped or Trail Deleted",
    explanation:
      "CloudTrail StopLogging was invoked on org-audit-trail by LegacyAdminRole from 198.51.100.42.",
    disposition: "open",
    disposition_reason: null,
    correlated_event_ids: ["ct-evt-1001", "ct-evt-1002"],
    data_source: "synthetic_fixture",
    event_time: "2026-11-23T14:32:00Z",
  },
  {
    id: "det-aws-002",
    rule_id: "DET-AWS-002",
    provider: "aws",
    account_ref: "123456789012",
    region: "us-east-1",
    event_name: "AttachRolePolicy",
    actor_identity: "arn:aws:iam::123456789012:user/ci-deployer",
    source_ip: "203.0.113.19",
    severity: "high",
    confidence: "high",
    mitre_tactic: "Privilege Escalation",
    mitre_technique: "T1098",
    title: "AdministratorAccess Policy Attached to IAM Principal",
    explanation:
      "IAM managed policy arn:aws:iam::aws:policy/AdministratorAccess was attached by user/ci-deployer.",
    disposition: "open",
    disposition_reason: null,
    correlated_event_ids: ["ct-evt-1009"],
    data_source: "synthetic_fixture",
    event_time: "2026-11-23T14:40:00Z",
  },
  {
    id: "det-az-001",
    rule_id: "DET-AZ-001",
    provider: "azure",
    account_ref: "00000000-1111-2222-3333-444444444444",
    region: "eastus",
    event_name: "Microsoft.Authorization/roleAssignments/write",
    actor_identity: "spn-automation@acme-demo.onmicrosoft.com",
    source_ip: "192.0.2.88",
    severity: "high",
    confidence: "high",
    mitre_tactic: "Persistence",
    mitre_technique: "T1098.003",
    title: "Privileged Azure RBAC Owner/Contributor Role Assignment Created",
    explanation:
      "Subscription-level Owner role assignment created by spn-automation@acme-demo.onmicrosoft.com.",
    disposition: "open",
    disposition_reason: null,
    correlated_event_ids: ["az-act-2001"],
    data_source: "synthetic_fixture",
    event_time: "2026-11-23T14:45:00Z",
  },
];

let demoAssessments: AssessmentRunItem[] = [
  {
    id: "run-aws-demo-1",
    connection_id: "conn-aws-demo-01",
    provider: "aws",
    status: "completed",
    data_source: "synthetic_fixture",
    assets_discovered: 5,
    checks_passed: 4,
    checks_failed: 6,
    checks_not_assessed: 0,
    checks_errored: 0,
    partial_failures: [],
    started_at: "2026-11-23T14:55:00Z",
    completed_at: "2026-11-23T14:55:04Z",
  },
  {
    id: "run-az-demo-2",
    connection_id: "conn-az-demo-02",
    provider: "azure",
    status: "completed",
    data_source: "synthetic_fixture",
    assets_discovered: 3,
    checks_passed: 3,
    checks_failed: 5,
    checks_not_assessed: 0,
    checks_errored: 0,
    partial_failures: [],
    started_at: "2026-11-23T14:56:00Z",
    completed_at: "2026-11-23T14:56:03Z",
  },
];

let demoRemediations: RemediationItem[] = [
  {
    id: "rem-demo-001",
    finding_id: "finding-aws-s3-001",
    provider: "aws",
    resource_id: "arn:aws:s3:::acme-prod-customer-exports",
    action_type: "aws_s3_enable_public_access_block",
    stage: "previewed",
    execution_mode: "dry_run",
    proposal: {
      api_call: "s3:PutPublicAccessBlock",
      parameters: {
        Bucket: "acme-prod-customer-exports",
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: true,
          IgnorePublicAcls: true,
          BlockPublicPolicy: true,
          RestrictPublicBuckets: true,
        },
      },
    },
    impact_analysis: {
      blast_radius: "Single S3 bucket (acme-prod-customer-exports)",
      breaking_change_risk: "Any unauthenticated public HTTP readers will be blocked.",
      reversible: true,
    },
    rollback_guidance:
      "Restore prior PublicAccessBlockConfiguration flags via aws s3api put-public-access-block if an authorized public distribution breaks.",
    proposed_by: "753a9d79-8e8e-4f3d-8992-de1369737799",
    approved_by: null,
    executed_by: null,
    verification_evidence: {},
    created_at: "2026-11-23T15:00:00Z",
  },
];

let demoAuditEvents: AuditEventItem[] = [
  {
    id: "audit-demo-1",
    actor_user_id: "b855519c-81bd-4d8a-8a2b-9b17aaa9da04",
    actor_role: "tenant_admin",
    action: "connection.validated",
    resource_type: "cloud_connection",
    resource_id: "conn-aws-demo-01",
    request_id: "req-demo-001",
    details: { provider: "aws", data_source: "synthetic_fixture", status: "healthy" },
    created_at: "2026-11-23T14:54:00Z",
  },
  {
    id: "audit-demo-2",
    actor_user_id: "b855519c-81bd-4d8a-8a2b-9b17aaa9da04",
    actor_role: "tenant_admin",
    action: "assessment.completed",
    resource_type: "assessment_run",
    resource_id: "run-aws-demo-1",
    request_id: "req-demo-002",
    details: { provider: "aws", checks_passed: 4, checks_failed: 6 },
    created_at: "2026-11-23T14:55:04Z",
  },
  {
    id: "audit-demo-3",
    actor_user_id: "753a9d79-8e8e-4f3d-8992-de1369737799",
    actor_role: "security_analyst",
    action: "remediation.previewed",
    resource_type: "remediation_request",
    resource_id: "rem-demo-001",
    request_id: "req-demo-003",
    details: { finding_id: "finding-aws-s3-001", execution_mode: "dry_run" },
    created_at: "2026-11-23T15:00:00Z",
  },
];

export function getDemoHealth(): HealthResponse {
  return {
    status: "ok",
    service: "cloudsentinel-demo-sandbox",
    version: "1.0.0",
    environment: "synthetic_demo_sandbox",
    timestamp: new Date().toISOString(),
  };
}

export function getDemoReadiness(): { httpStatus: number; data: ReadinessResponse } {
  return {
    httpStatus: 200,
    data: {
      status: "ready",
      service: "cloudsentinel-demo-sandbox",
      version: "1.0.0",
      timestamp: new Date().toISOString(),
      dependencies: {
        synthetic_fixture_store: {
          status: "up",
          latency_ms: 0.4,
          detail: "In-memory synthetic demonstration fixture store active",
        },
      },
    },
  };
}

export function getDemoSystemInfo(): SystemInfoResponse {
  return {
    product: "CloudSentinel",
    version: "1.0.0",
    environment: "synthetic_demo_sandbox",
    current_milestone: "M9 — Full Platform Foundation (v1.0 · Synthetic Demo Sandbox)",
    default_mode: "read_only",
    capabilities: {
      health_probes: true,
      oidc_auth: true,
      aws_connector: true,
      azure_connector: true,
      assessment_engine: true,
      threat_detection: true,
      compliance_mapping: true,
      remediation_engine: true,
    },
  };
}

export function getDemoCompliance(): ComplianceResponse {
  return {
    schema_version: "1.0.0",
    disclaimer:
      "Technical cloud posture checks provide partial, automated control evidence only. Passing technical checks NEVER establishes full organizational compliance with CIS, NIST CSF 2.0, or ISO/IEC 27001:2022.",
    frameworks: [
      {
        id: "cis_aws_v3",
        name: "CIS AWS Foundations Benchmark",
        version: "3.0.0",
        description: "Prescriptive security configuration baseline for Amazon Web Services.",
        summary: {
          total_controls: 6,
          passed: 2,
          failed: 4,
          not_assessed_or_error: 0,
          technical_pass_rate_pct: 33.3,
        },
        controls: [
          {
            control_id: "CIS-AWS-1.5",
            title: "Ensure MFA is enabled for the 'root' user account",
            related_rules: ["AWS-IAM-001"],
            status: "fail",
            rationale: "Protects highest-privilege account root identity.",
            coverage_status: "automated_technical",
            limitations: "Cannot verify physical custody of hardware MFA tokens.",
          },
          {
            control_id: "CIS-AWS-2.1.5",
            title: "Ensure that S3 Buckets are configured with 'Block public access'",
            related_rules: ["AWS-S3-001"],
            status: "fail",
            rationale: "Prevents accidental anonymous bucket exposure.",
            coverage_status: "automated_technical",
            limitations: "Evaluates bucket-level block settings only.",
          },
          {
            control_id: "CIS-AWS-3.1",
            title: "Ensure CloudTrail is enabled in all regions",
            related_rules: ["AWS-CT-001"],
            status: "pass",
            rationale: "Provides multi-region control-plane audit trail.",
            coverage_status: "automated_technical",
            limitations: "Does not verify downstream SIEM ingestion.",
          },
          {
            control_id: "CIS-AWS-5.2",
            title: "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports",
            related_rules: ["AWS-EC2-001"],
            status: "fail",
            rationale: "Reduces attack surface on SSH/RDP management ports.",
            coverage_status: "automated_technical",
            limitations: "Does not evaluate upstream Network Firewall policies.",
          },
        ],
      },
      {
        id: "cis_azure_v2_1",
        name: "CIS Microsoft Azure Foundations Benchmark",
        version: "2.1.0",
        description: "Prescriptive technical baseline for Microsoft Azure subscriptions.",
        summary: {
          total_controls: 5,
          passed: 2,
          failed: 3,
          not_assessed_or_error: 0,
          technical_pass_rate_pct: 40.0,
        },
        controls: [
          {
            control_id: "CIS-AZURE-3.7",
            title: "Ensure that 'Allow Blob Anonymous Access' is set to 'Disabled'",
            related_rules: ["AZ-STG-001"],
            status: "fail",
            rationale: "Prevents anonymous public read of Azure Blob containers.",
            coverage_status: "automated_technical",
            limitations: "ARM control-plane property check only.",
          },
          {
            control_id: "CIS-AZURE-6.1",
            title: "Ensure that RDP access from the Internet is evaluated and restricted",
            related_rules: ["AZ-NSG-001"],
            status: "fail",
            rationale: "Blocks direct internet brute-force attacks against TCP/3389.",
            coverage_status: "automated_technical",
            limitations: "Evaluates NSG rules; does not inspect Azure Firewall.",
          },
          {
            control_id: "CIS-AZURE-8.4",
            title: "Ensure the Key Vault is Recoverable (Soft Delete & Purge Protection)",
            related_rules: ["AZ-KV-001"],
            status: "fail",
            rationale: "Protects cryptographic keys and secrets against permanent deletion.",
            coverage_status: "automated_technical",
            limitations: "Metadata check only.",
          },
        ],
      },
      {
        id: "nist_csf_2_0",
        name: "NIST Cybersecurity Framework (CSF)",
        version: "2.0",
        description: "Core technical outcomes mapped to Protect and Detect functions.",
        summary: {
          total_controls: 4,
          passed: 1,
          failed: 3,
          not_assessed_or_error: 0,
          technical_pass_rate_pct: 25.0,
        },
        controls: [
          {
            control_id: "NIST-CSF-PR.DS-01",
            title: "Data-at-rest is protected against unauthorized access and exposure",
            related_rules: ["AWS-S3-001", "AZ-STG-001", "AZ-KV-001"],
            status: "fail",
            rationale: "Enforces encryption and public access blocks on cloud storage.",
            coverage_status: "partial_technical",
            limitations: "Covers cloud storage configuration only, not data classification policy.",
          },
          {
            control_id: "NIST-CSF-PR.AA-03",
            title: "Users, services, and hardware are authenticated with strong credentials",
            related_rules: ["AWS-IAM-001"],
            status: "fail",
            rationale: "Requires phishing-resistant MFA on privileged cloud accounts.",
            coverage_status: "partial_technical",
            limitations: "Does not inspect external corporate IdP conditional access policies.",
          },
        ],
      },
      {
        id: "iso_27001_2022",
        name: "ISO/IEC 27001:2022 Annex A",
        version: "2022",
        description: "Information security technical controls mapped to Annex A clauses.",
        summary: {
          total_controls: 4,
          passed: 1,
          failed: 3,
          not_assessed_or_error: 0,
          technical_pass_rate_pct: 25.0,
        },
        controls: [
          {
            control_id: "ISO27001-A.8.20",
            title: "Networks security — management and restriction of network perimeters",
            related_rules: ["AWS-EC2-001", "AZ-NSG-001"],
            status: "fail",
            rationale: "Restricts administrative ports on cloud security groups and NSGs.",
            coverage_status: "partial_technical",
            limitations: "Technical cloud perimeter check only; ISMS governance is out of scope.",
          },
        ],
      },
    ],
  };
}

export function getDemoDashboardSummary(provider?: "aws" | "azure"): DashboardSummary {
  const scopedConnections = provider
    ? demoConnections.filter((c) => c.provider === provider)
    : demoConnections;
  const scopedAssets = provider
    ? demoAssets.filter((a) => a.provider === provider)
    : demoAssets;
  const scopedFindings = provider
    ? demoFindings.filter((f) => f.provider === provider)
    : demoFindings;
  const openFindings = scopedFindings.filter((f) => f.status === "open");
  const scopedDetections = provider
    ? demoDetections.filter((d) => d.provider === provider)
    : demoDetections;

  return {
    tenant_id: DEMO_TENANT_ID,
    data_sources: ["synthetic_fixture"],
    contains_synthetic_fixtures: true,
    connections: {
      total: scopedConnections.length,
      healthy: scopedConnections.filter((c) => c.status === "healthy").length,
      error: 0,
      aws: scopedConnections.filter((c) => c.provider === "aws").length,
      azure: scopedConnections.filter((c) => c.provider === "azure").length,
    },
    cloud_inventory: {
      aws_accounts: demoConnections.filter((c) => c.provider === "aws").length,
      azure_subscriptions: demoConnections.filter((c) => c.provider === "azure").length,
      total_assets: scopedAssets.length,
    },
    findings: {
      total: scopedFindings.length,
      open: openFindings.length,
      resolved: scopedFindings.filter((f) => f.status === "resolved").length,
      risk_accepted: scopedFindings.filter((f) => f.status === "risk_accepted").length,
      by_severity: {
        critical: openFindings.filter((f) => f.severity === "critical").length,
        high: openFindings.filter((f) => f.severity === "high").length,
        medium: openFindings.filter((f) => f.severity === "medium").length,
        low: openFindings.filter((f) => f.severity === "low").length,
      },
    },
    detections: {
      total: scopedDetections.length,
      open: scopedDetections.filter((d) => d.disposition === "open").length,
      critical: scopedDetections.filter((d) => d.severity === "critical").length,
    },
    remediations: {
      total: demoRemediations.length,
      previewed: demoRemediations.filter((r) => r.stage === "previewed").length,
      approved: demoRemediations.filter((r) => r.stage === "approved").length,
      verified: demoRemediations.filter((r) => r.stage === "verified").length,
    },
    recent_assessments: demoAssessments.slice(0, 5),
    compliance_summary: getDemoCompliance().frameworks.map((fw) => ({
      id: fw.id,
      name: fw.name,
      version: fw.version,
      ...fw.summary,
    })),
  };
}

export function getDemoConnections(provider?: string) {
  const items = provider
    ? demoConnections.filter((c) => c.provider === provider)
    : demoConnections;
  return { total: items.length, items };
}

export function createDemoConnection(payload: Record<string, unknown>): CloudConnectionItem {
  const item: CloudConnectionItem = {
    id: `conn-demo-${Date.now()}`,
    name: String(payload.name ?? "Demo Cloud Connection"),
    provider: String(payload.provider ?? "aws"),
    auth_mode: String(payload.auth_mode ?? "sts_assume_role"),
    account_or_subscription_id: String(payload.account_or_subscription_id ?? "123456789012"),
    role_arn: payload.role_arn ? String(payload.role_arn) : null,
    azure_tenant_id: payload.azure_tenant_id ? String(payload.azure_tenant_id) : null,
    regions: Array.isArray(payload.regions) ? (payload.regions as string[]) : ["us-east-1"],
    status: "healthy",
    data_source: "synthetic_fixture",
    preflight_summary: { preflight: "synthetic_fixture_verified" },
    last_validated_at: new Date().toISOString(),
    created_at: new Date().toISOString(),
  };
  demoConnections = [item, ...demoConnections];
  return item;
}

export function triggerDemoAssessment(connectionId: string): AssessmentRunItem {
  const conn = demoConnections.find((c) => c.id === connectionId) ?? demoConnections[0];
  const run: AssessmentRunItem = {
    id: `run-demo-${Date.now()}`,
    connection_id: conn.id,
    provider: conn.provider,
    status: "completed",
    data_source: "synthetic_fixture",
    assets_discovered: conn.provider === "aws" ? 5 : 3,
    checks_passed: conn.provider === "aws" ? 4 : 3,
    checks_failed: conn.provider === "aws" ? 6 : 5,
    checks_not_assessed: 0,
    checks_errored: 0,
    partial_failures: [],
    started_at: new Date().toISOString(),
    completed_at: new Date().toISOString(),
  };
  demoAssessments = [run, ...demoAssessments];
  return run;
}

export function getDemoAssessments() {
  return { total: demoAssessments.length, items: demoAssessments };
}

export function getDemoAssets(params: { provider?: string; search?: string }) {
  const q = (params.search ?? "").trim().toLowerCase();
  const items = demoAssets.filter((a) => {
    if (params.provider && a.provider !== params.provider) return false;
    if (
      q &&
      !a.resource_name.toLowerCase().includes(q) &&
      !a.resource_id.toLowerCase().includes(q)
    ) {
      return false;
    }
    return true;
  });
  return { total: items.length, items };
}

export function getDemoFindings(params: {
  provider?: string;
  severity?: string;
  status?: string;
  search?: string;
}) {
  const q = (params.search ?? "").trim().toLowerCase();
  const items = demoFindings.filter((f) => {
    if (params.provider && f.provider !== params.provider) return false;
    if (params.severity && f.severity !== params.severity) return false;
    if (params.status && f.status !== params.status) return false;
    if (
      q &&
      !f.title.toLowerCase().includes(q) &&
      !f.rule_id.toLowerCase().includes(q) &&
      !f.resource_id.toLowerCase().includes(q)
    ) {
      return false;
    }
    return true;
  });
  return { total: items.length, items };
}

export function getDemoFindingDetail(id: string): FindingDetailResponse {
  const finding = demoFindings.find((f) => f.id === id) ?? demoFindings[0];
  return {
    finding,
    evidence: [
      {
        id: `ev-${finding.id}`,
        source: `${finding.provider.toUpperCase()} Read-Only Synthetic Fixture Collector`,
        expected_config:
          finding.rule_id === "AWS-S3-001"
            ? {
                BlockPublicAcls: true,
                IgnorePublicAcls: true,
                BlockPublicPolicy: true,
                RestrictPublicBuckets: true,
              }
            : { compliant: true, least_privilege_enforced: true },
        observed_config:
          finding.rule_id === "AWS-S3-001"
            ? {
                BlockPublicAcls: false,
                IgnorePublicAcls: false,
                BlockPublicPolicy: false,
                RestrictPublicBuckets: false,
              }
            : { compliant: false, exposed_to: "0.0.0.0/0", data_source: "synthetic_fixture" },
        raw_evidence_redacted: {
          account_ref: "[REDACTED_ACCOUNT]",
          resource_id: finding.resource_id,
          data_source: "synthetic_fixture",
        },
        collected_at: finding.last_seen_at,
      },
    ],
    history: [
      {
        id: `hist-${finding.id}-1`,
        previous_status: "new",
        new_status: finding.status,
        justification: "Initial deterministic evaluation from synthetic fixture assessment.",
        created_at: finding.first_seen_at,
      },
    ],
  };
}

export function updateDemoFindingStatus(
  id: string,
  status: string,
  justification: string,
  token: string
): FindingItem {
  const identity = getDemoIdentity(token);
  demoFindings = demoFindings.map((f) => (f.id === id ? { ...f, status } : f));
  const updated = demoFindings.find((f) => f.id === id) ?? demoFindings[0];
  demoAuditEvents = [
    {
      id: `audit-${Date.now()}`,
      actor_user_id: identity.user_id,
      actor_role: identity.role,
      action: "finding.status_updated",
      resource_type: "finding",
      resource_id: id,
      request_id: `req-${Date.now()}`,
      details: { new_status: status, justification },
      created_at: new Date().toISOString(),
    },
    ...demoAuditEvents,
  ];
  return updated;
}

export function getDemoIdentityAnalysis(): IdentityAnalysisResponse {
  return {
    reports: [
      {
        connection_id: "conn-aws-demo-01",
        connection_name: "AWS Production (Synthetic Fixture)",
        provider: "aws",
        account_ref: "123456789012",
        data_source: "synthetic_fixture",
        principals_reviewed: 8,
        findings: [
          {
            principal_id: "arn:aws:iam::123456789012:root",
            principal_type: "RootAccount",
            risk_category: "missing_root_mfa",
            severity: "critical",
            evidence: { AccountMFAEnabled: 0, AccessKeysPresent: 1 },
            recommendation: "Enable hardware FIDO2 MFA on root and delete root access keys.",
          },
          {
            principal_id: "arn:aws:iam::123456789012:role/LegacyDeploymentRole",
            principal_type: "IAMRole",
            risk_category: "wildcard_admin_policy",
            severity: "high",
            evidence: { Effect: "Allow", Action: "*", Resource: "*" },
            recommendation:
              "Replace Action:* with scoped service actions required by the workload.",
          },
        ],
        limitations: [
          "Static IAM policy inspection does not evaluate AWS Organizations SCP boundaries or runtime session policies.",
          "Cannot verify physical custody of hardware MFA authenticators.",
        ],
        generated_at: "2026-11-23T15:00:00Z",
      },
      {
        connection_id: "conn-az-demo-02",
        connection_name: "Azure Prod Subscription (Synthetic Fixture)",
        provider: "azure",
        account_ref: "00000000-1111-2222-3333-444444444444",
        data_source: "synthetic_fixture",
        principals_reviewed: 6,
        findings: [
          {
            principal_id: "spn-legacy-ci@acme-demo.onmicrosoft.com",
            principal_type: "ServicePrincipal",
            risk_category: "subscription_owner_service_principal",
            severity: "critical",
            evidence: { roleDefinitionName: "Owner", scope: "/subscriptions/00000000-..." },
            recommendation:
              "Downgrade Service Principal from Subscription Owner to resource-group scoped least-privilege role.",
          },
        ],
        limitations: [
          "Evaluates Azure ARM RBAC role assignments; Microsoft Entra ID Pim/Conditional Access policies require Graph API scope.",
        ],
        generated_at: "2026-11-23T15:00:00Z",
      },
    ],
  };
}

export function getDemoDetections() {
  return { total: demoDetections.length, items: demoDetections };
}

export function updateDemoDetectionDisposition(
  id: string,
  disposition: string,
  reason: string
): DetectionItem {
  demoDetections = demoDetections.map((d) =>
    d.id === id ? { ...d, disposition, disposition_reason: reason } : d
  );
  return demoDetections.find((d) => d.id === id) ?? demoDetections[0];
}

export function getDemoRemediations() {
  return { total: demoRemediations.length, items: demoRemediations };
}

export function previewDemoRemediation(findingId: string, token: string): RemediationItem {
  const identity = getDemoIdentity(token);
  const finding = demoFindings.find((f) => f.id === findingId) ?? demoFindings[0];
  const item: RemediationItem = {
    id: `rem-demo-${Date.now()}`,
    finding_id: finding.id,
    provider: finding.provider,
    resource_id: finding.resource_id,
    action_type: `${finding.provider}_remediate_${finding.rule_id.toLowerCase()}`,
    stage: "previewed",
    execution_mode: "dry_run",
    proposal: {
      rule_id: finding.rule_id,
      recommended_action: finding.remediation_guidance,
      mode: "dry_run_only",
    },
    impact_analysis: {
      target_resource: finding.resource_id,
      reversible: true,
    },
    rollback_guidance: `Revert configuration on ${finding.resource_id} using recorded pre-change snapshot.`,
    proposed_by: identity.user_id,
    approved_by: null,
    executed_by: null,
    verification_evidence: {},
    created_at: new Date().toISOString(),
  };
  demoRemediations = [item, ...demoRemediations];
  return item;
}

export function approveDemoRemediation(
  id: string,
  decision: "approved" | "rejected",
  token: string
): RemediationItem {
  const identity = getDemoIdentity(token);
  if (!identity.permissions.includes("remediations:approve")) {
    throw new Error("Role lacks required permission 'remediations:approve'.");
  }
  const target = demoRemediations.find((r) => r.id === id);
  if (!target) throw new Error("Remediation request not found.");
  if (target.proposed_by === identity.user_id) {
    throw new Error(
      "Separation of Duties violation: proposer cannot self-approve their own remediation request. Switch to the other demo persona."
    );
  }
  demoRemediations = demoRemediations.map((r) =>
    r.id === id ? { ...r, stage: decision, approved_by: identity.user_id } : r
  );
  return demoRemediations.find((r) => r.id === id) ?? target;
}

export function executeDemoRemediation(id: string, token: string): RemediationItem {
  const identity = getDemoIdentity(token);
  if (!identity.permissions.includes("remediations:execute")) {
    throw new Error("Role lacks required permission 'remediations:execute'.");
  }
  demoRemediations = demoRemediations.map((r) =>
    r.id === id
      ? {
          ...r,
          stage: "executed_unverified",
          execution_mode: "dry_run",
          verification_status: "dry_run_simulated",
          executed_by: identity.user_id,
          verification_evidence: {
            executed_at: new Date().toISOString(),
            mode: "dry_run",
            cloud_mutation_performed: false,
            finding_resolved: false,
            note: "Dry-run simulation only; no live cloud resource was modified and the finding remains open until verified by a live reassessment.",
          },
        }
      : r
  );
  return demoRemediations.find((r) => r.id === id) ?? demoRemediations[0];
}

export function getDemoAuditEvents() {
  return { total: demoAuditEvents.length, items: demoAuditEvents };
}
