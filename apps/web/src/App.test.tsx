import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AppRoutes, createQueryClient } from "./App";

function renderApp(initialPath = "/") {
  const queryClient = createQueryClient();
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[initialPath]}>
        <AppRoutes />
      </MemoryRouter>
    </QueryClientProvider>
  );
}

function jsonResponse(body: unknown, status = 200) {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    })
  );
}

const MOCK_AUTH = {
  user_id: "u1",
  tenant_id: "11111111-1111-1111-1111-111111111111",
  email: "admin@acme-demo.local",
  subject: "sub-admin",
  role: "tenant_admin",
  permissions: [
    "assessments:run",
    "connections:write",
    "findings:write",
    "detections:write",
    "remediations:preview",
    "remediations:approve",
    "remediations:execute",
  ],
};

const MOCK_SUMMARY = {
  tenant_id: "11111111-1111-1111-1111-111111111111",
  data_sources: ["synthetic_fixture"],
  contains_synthetic_fixtures: true,
  connections: { total: 2, healthy: 2, error: 0, aws: 1, azure: 1 },
  cloud_inventory: { aws_accounts: 1, azure_subscriptions: 1, total_assets: 12 },
  findings: {
    total: 9,
    open: 9,
    resolved: 0,
    risk_accepted: 0,
    by_severity: { critical: 3, high: 4, medium: 2, low: 0 },
  },
  detections: { total: 5, open: 5, critical: 2 },
  remediations: { total: 1, previewed: 1, approved: 0, verified: 0 },
  recent_assessments: [],
  compliance_summary: [],
};

afterEach(() => {
  vi.restoreAllMocks();
});

describe("CloudSentinel Security Intelligence Workspace", () => {
  it("renders live healthy and degraded 503 readiness telemetry on /system", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((input) => {
      const url = String(input);
      if (url.endsWith("/health")) {
        return jsonResponse({
          status: "ok",
          service: "cloudsentinel-api",
          version: "1.0.0",
          environment: "test",
          timestamp: "2026-11-23T13:30:00Z",
        });
      }
      if (url.endsWith("/ready")) {
        return jsonResponse(
          {
            status: "not_ready",
            service: "cloudsentinel-api",
            version: "1.0.0",
            timestamp: "2026-11-23T13:30:00Z",
            dependencies: {
              postgres: {
                status: "down",
                latency_ms: 1.5,
                detail: "PostgreSQL probe failed (ConnectionRefusedError)",
              },
              redis: {
                status: "up",
                latency_ms: 0.8,
                detail: null,
              },
            },
          },
          503
        );
      }
      return jsonResponse({
        product: "CloudSentinel",
        version: "1.0.0",
        environment: "test",
        current_milestone: "M9 — Full Platform Foundation (v1.0)",
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
      });
    });

    renderApp("/system");

    await waitFor(() => {
      expect(screen.getByText("Healthy")).toBeInTheDocument();
      expect(screen.getByText("Degraded (503)")).toBeInTheDocument();
    });
    expect(screen.getByText("PostgreSQL probe failed (ConnectionRefusedError)")).toBeInTheDocument();
  });

  it("renders redesigned Security Overview KPIs, provenance warning, and opens Command Palette on Ctrl+K", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((input) => {
      const url = String(input);
      if (url.includes("/api/v1/dashboard/summary")) return jsonResponse(MOCK_SUMMARY);
      if (url.includes("/api/v1/auth/me")) return jsonResponse(MOCK_AUTH);
      return jsonResponse({ total: 0, items: [] });
    });

    renderApp("/");

    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Security Overview" })).toBeInTheDocument();
      expect(screen.getByText(/synthetic demonstration fixtures/i)).toBeInTheDocument();
      expect(screen.getByText("Cloud Environments")).toBeInTheDocument();
      expect(screen.getByText("Compliance Coverage")).toBeInTheDocument();
    });

    // Verify Ctrl+K opens Command Palette
    fireEvent.keyDown(window, { key: "k", ctrlKey: true });
    expect(screen.getByRole("dialog", { name: "Command Palette" })).toBeInTheDocument();
  });

  it("renders dedicated AWS and Azure security workspaces with service posture breakdowns", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((input) => {
      const url = String(input);
      if (url.includes("/api/v1/dashboard/summary")) return jsonResponse(MOCK_SUMMARY);
      if (url.includes("/api/v1/auth/me")) return jsonResponse(MOCK_AUTH);
      if (url.includes("/api/v1/connections")) {
        return jsonResponse({
          total: 1,
          items: [
            {
              id: "conn-1",
              name: "AWS Sandbox Account",
              provider: "aws",
              auth_mode: "sts_assume_role",
              account_or_subscription_id: "123456789012",
              role_arn: "arn:aws:iam::123456789012:role/CloudSentinelReadOnly",
              azure_tenant_id: null,
              regions: ["us-east-1"],
              status: "healthy",
              data_source: "synthetic_fixture",
              preflight_summary: {},
              last_validated_at: "2026-11-23T15:00:00Z",
              created_at: "2026-11-23T14:00:00Z",
            },
          ],
        });
      }
      if (url.includes("/api/v1/assets")) {
        return jsonResponse({
          total: 1,
          items: [
            {
              id: "asset-1",
              provider: "aws",
              account_ref: "123456789012",
              resource_id: "arn:aws:s3:::public-logs-bucket",
              resource_name: "public-logs-bucket",
              resource_type: "aws_s3_bucket",
              region: "us-east-1",
              tags: { env: "sandbox" },
              collection_status: "collected",
              data_source: "synthetic_fixture",
              last_observed_at: "2026-11-23T15:00:00Z",
            },
          ],
        });
      }
      return jsonResponse({ total: 0, items: [] });
    });

    const { unmount } = renderApp("/aws");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "AWS Security Workspace" })).toBeInTheDocument();
      expect(screen.getByText("Amazon S3 Storage")).toBeInTheDocument();
      expect(screen.getByText("AWS Sandbox Account")).toBeInTheDocument();
    });
    unmount();

    renderApp("/azure");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Azure Security Workspace" })).toBeInTheDocument();
      expect(screen.getByText("Azure Storage Accounts")).toBeInTheDocument();
      expect(screen.getByText("Entra ID & Azure RBAC")).toBeInTheDocument();
    });
  });

  it("opens FindingDetailsDrawer from /findings row click and AssetDetailDrawer from /assets row click", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((input) => {
      const url = String(input);
      if (url.includes("/api/v1/auth/me")) return jsonResponse(MOCK_AUTH);
      if (url.includes("/api/v1/findings/f-1")) {
        return jsonResponse({
          finding: {
            id: "f-1",
            rule_id: "AWS-S3-001",
            rule_version: "1.0.0",
            provider: "aws",
            account_ref: "123456789012",
            resource_id: "arn:aws:s3:::demo-bucket",
            resource_type: "aws_s3_bucket",
            region: "us-east-1",
            title: "S3 bucket allows public access",
            description: "Block Public Access is disabled.",
            severity: "critical",
            confidence: "high",
            status: "open",
            risk_score: 92,
            risk_explanation: { exposure: "public" },
            remediation_guidance: "Enable S3 Block Public Access.",
            framework_mappings: ["CIS-AWS-2.1.5"],
            limitations: null,
            data_source: "synthetic_fixture",
            first_seen_at: "2026-11-23T14:00:00Z",
            last_seen_at: "2026-11-23T15:00:00Z",
          },
          evidence: [],
          history: [],
        });
      }
      if (url.includes("/api/v1/findings")) {
        return jsonResponse({
          total: 1,
          items: [
            {
              id: "f-1",
              rule_id: "AWS-S3-001",
              rule_version: "1.0.0",
              provider: "aws",
              account_ref: "123456789012",
              resource_id: "arn:aws:s3:::demo-bucket",
              resource_type: "aws_s3_bucket",
              region: "us-east-1",
              title: "S3 bucket allows public access",
              description: "Block Public Access is disabled.",
              severity: "critical",
              confidence: "high",
              status: "open",
              risk_score: 92,
              risk_explanation: {},
              remediation_guidance: "Enable S3 Block Public Access.",
              framework_mappings: [],
              limitations: null,
              data_source: "synthetic_fixture",
              first_seen_at: "2026-11-23T14:00:00Z",
              last_seen_at: "2026-11-23T15:00:00Z",
            },
          ],
        });
      }
      if (url.includes("/api/v1/assets")) {
        return jsonResponse({
          total: 1,
          items: [
            {
              id: "a-1",
              provider: "azure",
              account_ref: "sub-1",
              resource_id: "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st1",
              resource_name: "st1",
              resource_type: "azure_storage_account",
              region: "eastus",
              tags: { owner: "secops" },
              collection_status: "collected",
              data_source: "synthetic_fixture",
              last_observed_at: "2026-11-23T15:00:00Z",
            },
          ],
        });
      }
      return jsonResponse({ total: 0, items: [] });
    });

    const { unmount } = renderApp("/findings");
    await waitFor(() => {
      expect(screen.getByText("S3 bucket allows public access")).toBeInTheDocument();
    });
    fireEvent.click(screen.getByText("S3 bucket allows public access"));
    await waitFor(() => {
      expect(screen.getByRole("dialog", { name: "Finding Investigation Drawer" })).toBeInTheDocument();
      expect(screen.getByText("Enable S3 Block Public Access.")).toBeInTheDocument();
    });
    unmount();

    renderApp("/assets");
    await waitFor(() => {
      expect(screen.getByText("st1")).toBeInTheDocument();
    });
    fireEvent.click(screen.getByText("st1"));
    expect(screen.getByRole("dialog", { name: "Asset Inspection Drawer" })).toBeInTheDocument();
    expect(screen.getByText(/secops/i)).toBeInTheDocument();
  });

  it("renders Compliance Centre disclaimer and Remediation Centre separation-of-duties workflow", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((input) => {
      const url = String(input);
      if (url.includes("/api/v1/auth/me")) return jsonResponse(MOCK_AUTH);
      if (url.includes("/api/v1/compliance")) {
        return jsonResponse({
          schema_version: "1.0",
          disclaimer: "Automated technical control coverage is not formal audit certification.",
          frameworks: [
            {
              id: "cis-aws-3.0",
              name: "CIS AWS Foundations",
              version: "3.0.0",
              description: "CIS AWS technical checks",
              summary: {
                total_controls: 2,
                passed: 1,
                failed: 1,
                not_assessed_or_error: 0,
                technical_pass_rate_pct: 50,
              },
              controls: [
                {
                  control_id: "2.1.5",
                  title: "Ensure S3 Block Public Access is enabled",
                  related_rules: ["AWS-S3-001"],
                  status: "fail",
                  rationale: "Prevents accidental data exposure",
                  coverage_status: "automated",
                  limitations: "Does not inspect bucket ACL objects individually.",
                },
              ],
            },
          ],
        });
      }
      if (url.includes("/api/v1/remediations")) {
        return jsonResponse({
          total: 1,
          items: [
            {
              id: "rem-1",
              finding_id: "f-1",
              provider: "aws",
              resource_id: "arn:aws:s3:::demo-bucket",
              action_type: "enable_s3_block_public_access",
              stage: "previewed",
              execution_mode: "dry_run",
              proposal: { BlockPublicAcls: true },
              impact_analysis: { risk: "low" },
              rollback_guidance: "Restore prior PublicAccessBlock configuration.",
              proposed_by: "analyst-1",
              approved_by: null,
              executed_by: null,
              verification_evidence: {},
              created_at: "2026-11-23T15:00:00Z",
            },
          ],
        });
      }
      return jsonResponse({ total: 0, items: [] });
    });

    const { unmount } = renderApp("/compliance");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Compliance Centre" })).toBeInTheDocument();
      expect(screen.getByText(/not formal audit certification/i)).toBeInTheDocument();
      expect(screen.getByText(/Ensure S3 Block Public Access is enabled/i)).toBeInTheDocument();
    });
    unmount();

    renderApp("/remediations");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Remediation Centre" })).toBeInTheDocument();
      expect(screen.getByText(/Separation of Duties Active/i)).toBeInTheDocument();
      expect(screen.getByText("enable_s3_block_public_access")).toBeInTheDocument();
    });
    fireEvent.click(screen.getByText(/Inspect proposal & impact analysis/i));
    expect(screen.getByText(/BlockPublicAcls/i)).toBeInTheDocument();
  });

  it("renders explicit error state when dashboard API returns 401", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(() =>
      jsonResponse(
        { error: { code: "http_401", message: "Invalid or expired access token." } },
        401
      )
    );

    renderApp("/");

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent("Invalid or expired access token.");
    });
  });

  it("renders login view with CloudSentinel logo for OIDC authentication", () => {
    renderApp("/login");
    expect(screen.getByText("CloudSentinel Sign In")).toBeInTheDocument();
    expect(screen.getByLabelText("OIDC Access Token (JWT)")).toBeInTheDocument();
    expect(screen.getByAltText(/CloudSentinel/i)).toBeInTheDocument();
  });

  it("toggles collapsible sidebar cleanly", () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(() =>
      jsonResponse({ total: 0, items: [] })
    );
    renderApp("/reports");
    const collapseBtn = screen.getByRole("button", { name: "Collapse sidebar" });
    fireEvent.click(collapseBtn);
    expect(screen.getByRole("button", { name: "Expand sidebar" })).toBeInTheDocument();
  });
});
