export interface HealthResponse {
  status: "ok";
  service: string;
  version: string;
  environment: string;
  timestamp: string;
}

export interface DependencyCheck {
  status: "up" | "down";
  latency_ms: number;
  detail: string | null;
}

export interface ReadinessResponse {
  status: "ready" | "not_ready";
  service: string;
  version: string;
  timestamp: string;
  dependencies: Record<string, DependencyCheck>;
}

export interface SystemCapabilities {
  health_probes: boolean;
  oidc_auth: boolean;
  aws_connector: boolean;
  azure_connector: boolean;
  assessment_engine: boolean;
  threat_detection: boolean;
  compliance_mapping: boolean;
  remediation_engine: boolean;
}

export interface SystemInfoResponse {
  product: "CloudSentinel";
  version: string;
  environment: string;
  current_milestone: string;
  default_mode: "read_only";
  capabilities: SystemCapabilities;
}

export interface AuthIdentity {
  user_id: string;
  tenant_id: string;
  email: string;
  subject: string;
  role: string;
  permissions: string[];
}

export interface DashboardSummary {
  tenant_id: string;
  data_sources: string[];
  contains_synthetic_fixtures: boolean;
  connections: { total: number; healthy: number; error: number; aws: number; azure: number };
  cloud_inventory: { aws_accounts: number; azure_subscriptions: number; total_assets: number };
  findings: {
    total: number;
    open: number;
    resolved: number;
    risk_accepted: number;
    by_severity: { critical: number; high: number; medium: number; low: number };
  };
  detections: { total: number; open: number; critical: number };
  remediations: { total: number; previewed: number; approved: number; verified: number };
  recent_assessments: Array<{
    id: string;
    provider: string;
    status: string;
    data_source: string;
    checks_passed: number;
    checks_failed: number;
    started_at: string;
  }>;
  compliance_summary: Array<{
    id: string;
    name: string;
    version: string;
    total_controls: number;
    passed: number;
    failed: number;
    not_assessed_or_error: number;
    technical_pass_rate_pct: number | null;
  }>;
}

export interface CloudConnectionItem {
  id: string;
  name: string;
  provider: string;
  auth_mode: string;
  account_or_subscription_id: string;
  role_arn: string | null;
  azure_tenant_id: string | null;
  regions: string[];
  status: string;
  data_source: string;
  preflight_summary: Record<string, unknown>;
  last_validated_at: string | null;
  created_at: string;
}

export interface AssetItem {
  id: string;
  provider: string;
  account_ref: string;
  resource_id: string;
  resource_name: string;
  resource_type: string;
  region: string;
  tags: Record<string, unknown>;
  collection_status: string;
  data_source: string;
  last_observed_at: string;
}

export interface FindingItem {
  id: string;
  rule_id: string;
  rule_version: string;
  provider: string;
  account_ref: string;
  resource_id: string;
  resource_type: string;
  region: string;
  title: string;
  description: string;
  severity: string;
  confidence: string;
  status: string;
  risk_score: number;
  risk_explanation: Record<string, unknown>;
  remediation_guidance: string;
  framework_mappings: string[];
  limitations: string | null;
  data_source: string;
  first_seen_at: string;
  last_seen_at: string;
}

export interface FindingDetailResponse {
  finding: FindingItem;
  evidence: Array<{
    id: string;
    source: string;
    expected_config: Record<string, unknown>;
    observed_config: Record<string, unknown>;
    raw_evidence_redacted: Record<string, unknown>;
    collected_at: string;
  }>;
  history: Array<{
    id: string;
    previous_status: string;
    new_status: string;
    justification: string | null;
    created_at: string;
  }>;
}

export interface DetectionItem {
  id: string;
  rule_id: string;
  provider: string;
  account_ref: string;
  region: string;
  event_name: string;
  actor_identity: string;
  source_ip: string | null;
  severity: string;
  confidence: string;
  mitre_tactic: string;
  mitre_technique: string;
  title: string;
  explanation: string;
  disposition: string;
  disposition_reason: string | null;
  correlated_event_ids: string[];
  data_source: string;
  event_time: string;
}

export interface ComplianceResponse {
  schema_version: string;
  disclaimer: string;
  frameworks: Array<{
    id: string;
    name: string;
    version: string;
    description: string;
    summary: {
      total_controls: number;
      passed: number;
      failed: number;
      not_assessed_or_error: number;
      technical_pass_rate_pct: number | null;
    };
    controls: Array<{
      control_id: string;
      title: string;
      related_rules: string[];
      status: string;
      rationale: string;
      coverage_status: string;
      limitations: string;
    }>;
  }>;
}

export interface AssessmentRunItem {
  id: string;
  connection_id: string;
  provider: string;
  status: string;
  data_source: string;
  assets_discovered: number;
  checks_passed: number;
  checks_failed: number;
  checks_not_assessed: number;
  checks_errored: number;
  partial_failures: Array<Record<string, unknown>>;
  started_at: string;
  completed_at: string | null;
}

export interface RemediationItem {
  id: string;
  finding_id: string;
  provider: string;
  resource_id: string;
  action_type: string;
  stage: string;
  execution_mode: string;
  proposal: Record<string, unknown>;
  impact_analysis: Record<string, unknown>;
  rollback_guidance: string;
  proposed_by: string;
  approved_by: string | null;
  executed_by: string | null;
  verification_evidence: Record<string, unknown>;
  created_at: string;
}

export interface AuditEventItem {
  id: string;
  actor_user_id: string | null;
  actor_role: string;
  action: string;
  resource_type: string;
  resource_id: string;
  request_id: string;
  details: Record<string, unknown>;
  created_at: string;
}

export interface IdentityAnalysisResponse {
  reports: Array<{
    connection_id: string;
    connection_name: string;
    provider: string;
    account_ref: string;
    data_source: string;
    principals_reviewed: number;
    findings: Array<{
      principal_id: string;
      principal_type: string;
      risk_category: string;
      severity: string;
      evidence: Record<string, unknown>;
      recommendation: string;
    }>;
    limitations: string[];
    generated_at: string;
  }>;
}

const TOKEN_STORAGE_KEY = "cloudsentinel_access_token";

export const API_BASE_URL = (
  import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000"
).replace(/\/$/, "");

export function getStoredToken(): string {
  try {
    return window.sessionStorage.getItem(TOKEN_STORAGE_KEY) ?? "";
  } catch {
    return "";
  }
}

export function setStoredToken(token: string): void {
  try {
    if (token) {
      window.sessionStorage.setItem(TOKEN_STORAGE_KEY, token.trim());
    } else {
      window.sessionStorage.removeItem(TOKEN_STORAGE_KEY);
    }
  } catch {
    // Ignore storage errors in restricted contexts
  }
}

async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getStoredToken();
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const response = await fetch(`${API_BASE_URL}${path}`, { ...init, headers });
  if (!response.ok) {
    let message = `HTTP ${response.status}`;
    try {
      const errBody = (await response.json()) as { error?: { message?: string } };
      if (errBody?.error?.message) {
        message = errBody.error.message;
      }
    } catch {
      // Keep status message
    }
    throw new Error(message);
  }
  return (await response.json()) as T;
}

export async function fetchHealth(): Promise<HealthResponse> {
  return apiFetch<HealthResponse>("/health");
}

export async function fetchReadiness(): Promise<{ httpStatus: number; data: ReadinessResponse }> {
  const response = await fetch(`${API_BASE_URL}/ready`, { headers: { Accept: "application/json" } });
  if (response.status !== 200 && response.status !== 503) {
    throw new Error(`Readiness endpoint returned HTTP ${response.status}`);
  }
  const data = (await response.json()) as ReadinessResponse;
  return { httpStatus: response.status, data };
}

export async function fetchSystemInfo(): Promise<SystemInfoResponse> {
  return apiFetch<SystemInfoResponse>("/api/v1/system/info");
}

export async function fetchAuthMe(): Promise<AuthIdentity> {
  return apiFetch<AuthIdentity>("/api/v1/auth/me");
}

export async function fetchDashboardSummary(provider?: "aws" | "azure"): Promise<DashboardSummary> {
  const qs = provider ? `?provider=${provider}` : "";
  return apiFetch<DashboardSummary>(`/api/v1/dashboard/summary${qs}`);
}

export async function fetchConnections(provider?: string): Promise<{ total: number; items: CloudConnectionItem[] }> {
  const qs = provider ? `?provider=${encodeURIComponent(provider)}` : "";
  return apiFetch(`/api/v1/connections${qs}`);
}

export async function createConnection(payload: Record<string, unknown>): Promise<CloudConnectionItem> {
  return apiFetch("/api/v1/connections", { method: "POST", body: JSON.stringify(payload) });
}

export async function validateConnection(id: string): Promise<Record<string, unknown>> {
  return apiFetch(`/api/v1/connections/${id}/validate`, { method: "POST" });
}

export async function triggerAssessment(connectionId: string): Promise<AssessmentRunItem> {
  return apiFetch("/api/v1/assessments", {
    method: "POST",
    body: JSON.stringify({ connection_id: connectionId }),
  });
}

export async function fetchAssessments(): Promise<{ total: number; items: AssessmentRunItem[] }> {
  return apiFetch("/api/v1/assessments");
}

export async function fetchAssets(params: {
  provider?: string;
  search?: string;
  offset?: number;
}): Promise<{ total: number; items: AssetItem[] }> {
  const sp = new URLSearchParams();
  if (params.provider) sp.set("provider", params.provider);
  if (params.search) sp.set("search", params.search);
  if (params.offset) sp.set("offset", String(params.offset));
  const qs = sp.toString() ? `?${sp.toString()}` : "";
  return apiFetch(`/api/v1/assets${qs}`);
}

export async function fetchFindings(params: {
  provider?: string;
  severity?: string;
  status?: string;
  search?: string;
}): Promise<{ total: number; items: FindingItem[] }> {
  const sp = new URLSearchParams();
  if (params.provider) sp.set("provider", params.provider);
  if (params.severity) sp.set("severity", params.severity);
  if (params.status) sp.set("status", params.status);
  if (params.search) sp.set("search", params.search);
  const qs = sp.toString() ? `?${sp.toString()}` : "";
  return apiFetch(`/api/v1/findings${qs}`);
}

export async function fetchFindingDetail(id: string): Promise<FindingDetailResponse> {
  return apiFetch(`/api/v1/findings/${id}`);
}

export async function updateFindingStatus(
  id: string,
  status: string,
  justification: string
): Promise<FindingItem> {
  return apiFetch(`/api/v1/findings/${id}`, {
    method: "PATCH",
    body: JSON.stringify({ status, justification }),
  });
}

export async function fetchIdentityAnalysis(): Promise<IdentityAnalysisResponse> {
  return apiFetch("/api/v1/identity/analysis");
}

export async function fetchDetections(): Promise<{ total: number; items: DetectionItem[] }> {
  return apiFetch("/api/v1/detections");
}

export async function updateDetectionDisposition(
  id: string,
  disposition: string,
  reason: string
): Promise<DetectionItem> {
  return apiFetch(`/api/v1/detections/${id}`, {
    method: "PATCH",
    body: JSON.stringify({ disposition, reason }),
  });
}

export async function fetchCompliance(): Promise<ComplianceResponse> {
  return apiFetch("/api/v1/compliance");
}

export async function fetchRemediations(): Promise<{ total: number; items: RemediationItem[] }> {
  return apiFetch("/api/v1/remediations");
}

export async function previewRemediation(findingId: string): Promise<RemediationItem> {
  return apiFetch("/api/v1/remediations/preview", {
    method: "POST",
    body: JSON.stringify({ finding_id: findingId }),
  });
}

export async function approveRemediation(
  id: string,
  decision: "approved" | "rejected",
  comment: string
): Promise<RemediationItem> {
  return apiFetch(`/api/v1/remediations/${id}/approve`, {
    method: "POST",
    body: JSON.stringify({ decision, comment }),
  });
}

export async function executeRemediation(id: string): Promise<RemediationItem> {
  return apiFetch(`/api/v1/remediations/${id}/execute`, {
    method: "POST",
    body: JSON.stringify({ confirm_live: false }),
  });
}

export async function fetchAuditEvents(): Promise<{ total: number; items: AuditEventItem[] }> {
  return apiFetch("/api/v1/audit-events");
}

export async function downloadReport(params: {
  reportType: string;
  format: "json" | "csv" | "pdf";
  provider?: string;
  redact: boolean;
}): Promise<Blob> {
  const sp = new URLSearchParams({
    report_type: params.reportType,
    format: params.format,
    redact: String(params.redact),
  });
  if (params.provider) sp.set("provider", params.provider);
  const headers = new Headers();
  const token = getStoredToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const response = await fetch(`${API_BASE_URL}/api/v1/reports?${sp.toString()}`, { headers });
  if (!response.ok) {
    throw new Error(`Report export failed (HTTP ${response.status})`);
  }
  return response.blob();
}
