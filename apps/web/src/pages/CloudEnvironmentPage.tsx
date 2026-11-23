import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Cloud,
  Database,
  HardDrive,
  KeyRound,
  Network,
  Play,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import {
  fetchAssessments,
  fetchAssets,
  fetchAuthMe,
  fetchConnections,
  fetchDashboardSummary,
  fetchDetections,
  fetchFindings,
  triggerAssessment,
  type AssetItem,
  type FindingItem,
} from "../lib/api";
import {
  ConnectorStatus,
  DataSourceBadge,
  ProviderBadge,
  RiskScoreBar,
  SeverityBadge,
  StatusBadge,
} from "../components/Badges";
import { FindingDetailsDrawer } from "../components/FindingDetailsDrawer";
import { MetricCard } from "../components/MetricCard";
import { EmptyState, ErrorBanner, LoadingState, PageHeader, Panel } from "../components/UI";

interface ServiceCategorySpec {
  id: string;
  label: string;
  description: string;
  icon: typeof Server;
  matches: (resourceType: string, ruleId?: string) => boolean;
}

const AWS_SERVICE_CATEGORIES: ServiceCategorySpec[] = [
  {
    id: "iam",
    label: "IAM & Access Control",
    description: "Root MFA, password policies, wildcard roles & access keys",
    icon: KeyRound,
    matches: (rt, rule) =>
      rt.includes("iam") || (rule ?? "").toLowerCase().includes("iam"),
  },
  {
    id: "s3",
    label: "Amazon S3 Storage",
    description: "Public access blocks, bucket policies & default encryption",
    icon: Database,
    matches: (rt, rule) =>
      rt.includes("s3") || (rule ?? "").toLowerCase().includes("s3"),
  },
  {
    id: "ec2-net",
    label: "EC2, EBS & Security Groups",
    description: "Unrestricted ingress (22/3389), EBS encryption & IMDSv2",
    icon: Network,
    matches: (rt, rule) =>
      rt.includes("ec2") ||
      rt.includes("security_group") ||
      rt.includes("ebs") ||
      rt.includes("vpc") ||
      (rule ?? "").toLowerCase().includes("ec2") ||
      (rule ?? "").toLowerCase().includes("sg"),
  },
  {
    id: "logging",
    label: "CloudTrail & Audit Logging",
    description: "Multi-region trails, log validation & KMS encryption",
    icon: Activity,
    matches: (rt, rule) =>
      rt.includes("cloudtrail") ||
      rt.includes("trail") ||
      rt.includes("log") ||
      (rule ?? "").toLowerCase().includes("ct"),
  },
  {
    id: "rds-other",
    label: "RDS & Managed Services",
    description: "Public database snapshots, storage encryption & other services",
    icon: HardDrive,
    matches: (rt, rule) =>
      rt.includes("rds") ||
      rt.includes("kms") ||
      (rule ?? "").toLowerCase().includes("rds"),
  },
];

const AZURE_SERVICE_CATEGORIES: ServiceCategorySpec[] = [
  {
    id: "entra-rbac",
    label: "Entra ID & Azure RBAC",
    description: "Subscription Owner/Contributor assignments & service principals",
    icon: KeyRound,
    matches: (rt, rule) =>
      rt.includes("role") ||
      rt.includes("rbac") ||
      rt.includes("identity") ||
      rt.includes("entra") ||
      rt.includes("principal") ||
      (rule ?? "").toLowerCase().includes("iam") ||
      (rule ?? "").toLowerCase().includes("rbac"),
  },
  {
    id: "storage",
    label: "Azure Storage Accounts",
    description: "Public blob access, HTTPS-only & minimum TLS 1.2 enforcement",
    icon: Database,
    matches: (rt, rule) =>
      rt.includes("storage") ||
      rt.includes("blob") ||
      (rule ?? "").toLowerCase().includes("stg"),
  },
  {
    id: "network",
    label: "Network Security Groups",
    description: "NSG inbound rules exposing SSH (22), RDP (3389) or Any/*",
    icon: Network,
    matches: (rt, rule) =>
      rt.includes("nsg") ||
      rt.includes("network") ||
      (rule ?? "").toLowerCase().includes("nsg"),
  },
  {
    id: "keyvault-diag",
    label: "Key Vault & Diagnostics",
    description: "Soft-delete, purge protection & subscription diagnostic logs",
    icon: ShieldCheck,
    matches: (rt, rule) =>
      rt.includes("vault") ||
      rt.includes("diagnostic") ||
      rt.includes("monitor") ||
      rt.includes("activity") ||
      (rule ?? "").toLowerCase().includes("kv") ||
      (rule ?? "").toLowerCase().includes("log"),
  },
  {
    id: "compute",
    label: "Virtual Machines & SQL",
    description: "Disk encryption, managed identities & SQL firewall controls",
    icon: Server,
    matches: (rt, rule) =>
      rt.includes("vm") ||
      rt.includes("virtual_machine") ||
      rt.includes("compute") ||
      rt.includes("sql") ||
      (rule ?? "").toLowerCase().includes("vm") ||
      (rule ?? "").toLowerCase().includes("sql"),
  },
];

function summarizeServices(
  specs: ServiceCategorySpec[],
  assets: AssetItem[],
  findings: FindingItem[]
) {
  return specs.map((spec) => {
    const matchedAssets = assets.filter((a) =>
      spec.matches(a.resource_type.toLowerCase())
    );
    const matchedFindings = findings.filter((f) =>
      spec.matches(f.resource_type.toLowerCase(), f.rule_id)
    );
    const openFindings = matchedFindings.filter((f) => f.status === "open");
    const criticalHigh = openFindings.filter(
      (f) => f.severity === "critical" || f.severity === "high"
    );
    return {
      ...spec,
      assetCount: matchedAssets.length,
      openCount: openFindings.length,
      criticalHighCount: criticalHigh.length,
    };
  });
}

export function CloudEnvironmentPage({ provider }: { provider: "aws" | "azure" }) {
  const isAws = provider === "aws";
  const qc = useQueryClient();

  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [runFeedback, setRunFeedback] = useState<string | null>(null);

  const authQuery = useQuery({
    queryKey: ["auth-me"],
    queryFn: fetchAuthMe,
    retry: false,
  });

  const summaryQuery = useQuery({
    queryKey: ["dashboard-summary", provider],
    queryFn: () => fetchDashboardSummary(provider),
    retry: false,
  });

  const connectionsQuery = useQuery({
    queryKey: ["connections", provider],
    queryFn: () => fetchConnections(provider),
    retry: false,
  });

  const assetsQuery = useQuery({
    queryKey: ["assets", provider, "workspace"],
    queryFn: () => fetchAssets({ provider }),
    retry: false,
  });

  const findingsQuery = useQuery({
    queryKey: ["findings", provider, "workspace"],
    queryFn: () => fetchFindings({ provider }),
    retry: false,
  });

  const assessmentsQuery = useQuery({
    queryKey: ["assessments"],
    queryFn: fetchAssessments,
    retry: false,
  });

  const detectionsQuery = useQuery({
    queryKey: ["detections"],
    queryFn: fetchDetections,
    retry: false,
  });

  const canRunAssessment = Boolean(
    authQuery.data?.permissions.includes("assessments:run")
  );
  const canPreviewRemediation = Boolean(
    authQuery.data?.permissions.includes("remediations:preview")
  );

  const runAssessmentMut = useMutation({
    mutationFn: (connectionId: string) => triggerAssessment(connectionId),
    onSuccess: (run) => {
      setRunFeedback(
        `${provider.toUpperCase()} assessment completed: ${run.checks_passed} PASS, ${run.checks_failed} FAIL, ${run.assets_discovered} assets discovered.`
      );
      void qc.invalidateQueries({ queryKey: ["dashboard-summary"] });
      void qc.invalidateQueries({ queryKey: ["findings"] });
      void qc.invalidateQueries({ queryKey: ["assets"] });
      void qc.invalidateQueries({ queryKey: ["assessments"] });
    },
    onError: (err: Error) => {
      setRunFeedback(`Assessment error: ${err.message}`);
    },
  });

  const providerConnections = connectionsQuery.data?.items ?? [];
  const providerAssets = assetsQuery.data?.items ?? [];
  const providerFindings = findingsQuery.data?.items ?? [];
  const providerRuns = useMemo(
    () =>
      (assessmentsQuery.data?.items ?? []).filter(
        (r) => r.provider.toLowerCase() === provider
      ),
    [assessmentsQuery.data, provider]
  );
  const providerDetections = useMemo(
    () =>
      (detectionsQuery.data?.items ?? []).filter(
        (d) => d.provider.toLowerCase() === provider
      ),
    [detectionsQuery.data, provider]
  );

  const serviceBreakdown = useMemo(
    () =>
      summarizeServices(
        isAws ? AWS_SERVICE_CATEGORIES : AZURE_SERVICE_CATEGORIES,
        providerAssets,
        providerFindings
      ),
    [isAws, providerAssets, providerFindings]
  );

  const activeRegions = useMemo(() => {
    const set = new Set<string>();
    providerConnections.forEach((c) => c.regions.forEach((r) => set.add(r)));
    providerAssets.forEach((a) => {
      if (a.region) set.add(a.region);
    });
    return Array.from(set).sort();
  }, [providerConnections, providerAssets]);

  const filteredFindings = useMemo(() => {
    const q = search.trim().toLowerCase();
    return providerFindings.filter((f) => {
      if (severityFilter && f.severity.toLowerCase() !== severityFilter) {
        return false;
      }
      if (!q) return true;
      return (
        f.rule_id.toLowerCase().includes(q) ||
        f.title.toLowerCase().includes(q) ||
        f.resource_id.toLowerCase().includes(q) ||
        f.region.toLowerCase().includes(q)
      );
    });
  }, [providerFindings, search, severityFilter]);

  const healthyCount = providerConnections.filter(
    (c) => c.status.toLowerCase() === "healthy"
  ).length;

  const handleRefreshAll = () => {
    void summaryQuery.refetch();
    void connectionsQuery.refetch();
    void assetsQuery.refetch();
    void findingsQuery.refetch();
    void assessmentsQuery.refetch();
    void detectionsQuery.refetch();
  };

  if (summaryQuery.isPending && connectionsQuery.isPending) {
    return (
      <LoadingState
        label={`Loading ${isAws ? "AWS" : "Microsoft Azure"} security workspace...`}
      />
    );
  }

  if (summaryQuery.isError) {
    return <ErrorBanner message={summaryQuery.error.message} />;
  }

  const summary = summaryQuery.data;
  const openCriticalHigh =
    (summary?.findings.by_severity.critical ?? 0) +
    (summary?.findings.by_severity.high ?? 0);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow={
          isAws
            ? "Amazon Web Services · Read-Only STS Assessment"
            : "Microsoft Azure · Read-Only ARM & RBAC Assessment"
        }
        title={isAws ? "AWS Security Workspace" : "Azure Security Workspace"}
        description={
          isAws
            ? "Dedicated security posture across connected AWS accounts, IAM controls, S3 storage, EC2/VPC networking, CloudTrail telemetry, and deterministic rule findings."
            : "Dedicated security posture across connected Azure subscriptions, Entra/RBAC assignments, Storage accounts, NSGs, Key Vaults, Activity Logs, and deterministic rule findings."
        }
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <ProviderBadge provider={provider} />
            {summary?.contains_synthetic_fixtures ? (
              <DataSourceBadge source="synthetic_fixture" />
            ) : (
              <DataSourceBadge source="live" />
            )}
            <button
              type="button"
              onClick={handleRefreshAll}
              className="inline-flex items-center gap-1.5 rounded-[8px] border border-[#243142] bg-[#172131] px-3 py-2 text-xs font-medium text-[#A0AEC0] hover:bg-[#1C293A] hover:text-[#F1F5F9]"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              <span>Refresh</span>
            </button>
            {providerConnections.length > 0 && (
              <button
                type="button"
                disabled={!canRunAssessment || runAssessmentMut.isPending}
                title={
                  canRunAssessment
                    ? `Run read-only assessment on ${providerConnections[0].name}`
                    : "Requires assessments:run permission"
                }
                onClick={() => runAssessmentMut.mutate(providerConnections[0].id)}
                className="inline-flex items-center gap-1.5 rounded-[8px] border border-[#00D6A0]/40 bg-[#00D6A0]/15 px-3.5 py-2 text-xs font-semibold text-[#00D6A0] hover:bg-[#00D6A0]/25 disabled:cursor-not-allowed disabled:opacity-45"
              >
                <Play className="h-3.5 w-3.5" />
                <span>
                  {runAssessmentMut.isPending
                    ? "Assessing..."
                    : `Run ${isAws ? "AWS" : "Azure"} Assessment`}
                </span>
              </button>
            )}
          </div>
        }
      />

      {summary?.contains_synthetic_fixtures && (
        <div className="flex flex-wrap items-center justify-between gap-2 rounded-[12px] border border-[#F59E0B]/35 bg-[#F59E0B]/10 px-4 py-3 text-xs text-[#F1F5F9]">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 shrink-0 text-[#F59E0B]" />
            <span>
              <strong>Synthetic Fixture Data Present:</strong> One or more{" "}
              {isAws ? "AWS" : "Azure"} records in this workspace originate from
              non-production demo fixtures (
              <code className="font-mono text-[#F59E0B]">
                data_source=&quot;synthetic_fixture&quot;
              </code>
              ).
            </span>
          </div>
          <Link
            to="/connections"
            className="font-semibold text-[#00D6A0] hover:underline"
          >
            Connect live {isAws ? "AWS account" : "Azure subscription"} →
          </Link>
        </div>
      )}

      {runFeedback && (
        <div className="flex items-center justify-between gap-2 rounded-[12px] border border-[#00D6A0]/35 bg-[#00D6A0]/10 px-4 py-3 text-xs text-[#F1F5F9]">
          <span>{runFeedback}</span>
          <button
            type="button"
            onClick={() => setRunFeedback(null)}
            className="text-[#A0AEC0] hover:text-[#F1F5F9]"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* KPI Row */}
      <section
        aria-label={`${isAws ? "AWS" : "Azure"} Security Summary`}
        className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5"
      >
        <MetricCard
          label={isAws ? "AWS Accounts" : "Azure Subscriptions"}
          value={providerConnections.length}
          subtitle={`${healthyCount} healthy connector${healthyCount === 1 ? "" : "s"}`}
          icon={Cloud}
          accent={isAws ? "warning" : "info"}
          to="/connections"
        />
        <MetricCard
          label="Discovered Assets"
          value={assetsQuery.data?.total ?? 0}
          subtitle={`${activeRegions.length} active region${activeRegions.length === 1 ? "" : "s"}`}
          icon={Server}
          accent="neutral"
          to="/assets"
        />
        <MetricCard
          label="Open Findings"
          value={summary?.findings.open ?? 0}
          subtitle={`${summary?.findings.total ?? 0} total evaluated`}
          icon={ShieldAlert}
          accent={(summary?.findings.open ?? 0) > 0 ? "high" : "success"}
          to="/findings"
        />
        <MetricCard
          label="Critical & High"
          value={openCriticalHigh}
          subtitle={`${summary?.findings.by_severity.critical ?? 0} critical · ${summary?.findings.by_severity.high ?? 0} high`}
          icon={AlertTriangle}
          accent={openCriticalHigh > 0 ? "critical" : "success"}
          to="/findings"
        />
        <MetricCard
          label={isAws ? "CloudTrail Detections" : "Activity Detections"}
          value={providerDetections.length}
          subtitle={`${providerDetections.filter((d) => d.disposition === "open").length} open triage`}
          icon={Activity}
          accent={providerDetections.length > 0 ? "warning" : "success"}
          to="/detections"
        />
      </section>

      {/* Connected Accounts/Subscriptions + Active Regions */}
      <div className="grid gap-5 lg:grid-cols-3">
        <Panel
          title={isAws ? "Connected AWS Accounts" : "Connected Azure Subscriptions"}
          subtitle="Read-only connector scope & validation status"
          className="lg:col-span-2"
          action={
            <ConnectorStatus healthy={healthyCount} total={providerConnections.length} />
          }
        >
          {providerConnections.length === 0 ? (
            <EmptyState
              title={`No ${isAws ? "AWS Accounts" : "Azure Subscriptions"} Connected`}
              description={`Register a read-only ${isAws ? "AWS STS AssumeRole" : "Azure Managed Identity"} connector to discover assets and run posture checks.`}
              action={
                <Link
                  to="/connections"
                  className="inline-flex items-center gap-1.5 rounded-[8px] border border-[#00D6A0]/40 bg-[#00D6A0]/15 px-3.5 py-2 text-xs font-semibold text-[#00D6A0] hover:bg-[#00D6A0]/25"
                >
                  <span>Connect {isAws ? "AWS" : "Azure"}</span>
                  <ArrowRight className="h-3.5 w-3.5" />
                </Link>
              }
            />
          ) : (
            <div className="space-y-3">
              {providerConnections.map((conn) => (
                <div
                  key={conn.id}
                  className="flex flex-wrap items-center justify-between gap-3 rounded-[10px] border border-[#243142] bg-[#172131]/65 p-3.5"
                >
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-semibold text-[#F1F5F9]">
                        {conn.name}
                      </span>
                      <StatusBadge status={conn.status} />
                      <DataSourceBadge source={conn.data_source} />
                    </div>
                    <div className="font-mono text-[11px] text-[#A0AEC0]">
                      {isAws ? "Account" : "Subscription"}:{" "}
                      <span className="text-[#F1F5F9]">
                        {conn.account_or_subscription_id}
                      </span>{" "}
                      · Auth: {conn.auth_mode}
                    </div>
                    {conn.role_arn && (
                      <div className="font-mono text-[11px] text-[#64748B] break-all">
                        Role: {conn.role_arn}
                      </div>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      disabled={!canRunAssessment || runAssessmentMut.isPending}
                      onClick={() => runAssessmentMut.mutate(conn.id)}
                      className="inline-flex items-center gap-1.5 rounded-[8px] border border-[#00D6A0]/35 bg-[#00D6A0]/10 px-3 py-1.5 text-xs font-semibold text-[#00D6A0] hover:bg-[#00D6A0]/20 disabled:cursor-not-allowed disabled:opacity-45"
                    >
                      <Play className="h-3 w-3" />
                      <span>Assess</span>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel
          title="Observed Regions & Coverage"
          subtitle="Regions discovered across connectors & assets"
        >
          {activeRegions.length === 0 ? (
            <p className="text-xs text-[#64748B]">
              No regions observed yet. Validate a connector or run an assessment.
            </p>
          ) : (
            <div className="space-y-4">
              <div className="flex flex-wrap gap-1.5">
                {activeRegions.map((reg) => (
                  <span
                    key={reg}
                    className="rounded-md border border-[#243142] bg-[#172131] px-2.5 py-1 font-mono text-[11px] text-[#F1F5F9]"
                  >
                    {reg}
                  </span>
                ))}
              </div>
              <div className="rounded-[10px] border border-[#243142] bg-[#0C121B] p-3 text-xs text-[#A0AEC0] space-y-1.5">
                <div className="font-semibold text-[#F1F5F9]">
                  Read-Only Collection Boundary
                </div>
                <p className="text-[11px] leading-relaxed text-[#64748B]">
                  {isAws
                    ? "Assesses AWS accounts strictly through cross-account STS AssumeRole with least-privilege read-only IAM policy manifest. No write actions occur during discovery."
                    : "Assesses Azure subscriptions strictly through Managed or Workload Identity with Reader & Security Reader scope. No write actions occur during discovery."}
                </p>
              </div>
            </div>
          )}
        </Panel>
      </div>

      {/* Service Posture Breakdown */}
      <Panel
        title={`${isAws ? "AWS" : "Azure"} Service Security Breakdown`}
        subtitle="Real asset discovery and open misconfiguration counts grouped by cloud service"
      >
        <div className="grid gap-3.5 sm:grid-cols-2 lg:grid-cols-5">
          {serviceBreakdown.map((svc) => {
            const Icon = svc.icon;
            const hasRisk = svc.criticalHighCount > 0;
            return (
              <div
                key={svc.id}
                className="flex flex-col justify-between rounded-[10px] border border-[#243142] bg-[#172131]/65 p-4"
              >
                <div>
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex h-8 w-8 items-center justify-center rounded-[8px] border border-[#243142] bg-[#0C121B] text-[#00D6A0]">
                      <Icon className="h-4 w-4" />
                    </div>
                    <span
                      className={`rounded-md border px-2 py-0.5 font-mono text-[10px] font-semibold ${
                        hasRisk
                          ? "border-[#F43F5E]/35 bg-[#F43F5E]/10 text-[#F43F5E]"
                          : svc.openCount > 0
                            ? "border-[#F59E0B]/35 bg-[#F59E0B]/10 text-[#F59E0B]"
                            : svc.assetCount > 0
                              ? "border-[#10B981]/35 bg-[#10B981]/10 text-[#10B981]"
                              : "border-[#243142] bg-[#0C121B] text-[#64748B]"
                      }`}
                    >
                      {hasRisk
                        ? `${svc.criticalHighCount} CRIT/HIGH`
                        : svc.openCount > 0
                          ? `${svc.openCount} OPEN`
                          : svc.assetCount > 0
                            ? "CLEAN"
                            : "NOT ASSESSED"}
                    </span>
                  </div>
                  <h3 className="mt-3 text-xs font-semibold text-[#F1F5F9]">
                    {svc.label}
                  </h3>
                  <p className="mt-1 text-[11px] leading-relaxed text-[#64748B]">
                    {svc.description}
                  </p>
                </div>
                <div className="mt-4 flex items-center justify-between border-t border-[#243142] pt-2.5 font-mono text-[11px] tabular-nums">
                  <span className="text-[#A0AEC0]">{svc.assetCount} assets</span>
                  <span
                    className={
                      svc.openCount > 0 ? "text-[#F97316]" : "text-[#10B981]"
                    }
                  >
                    {svc.openCount} open
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </Panel>

      {/* Interactive Provider Findings Table */}
      <Panel
        title={`${isAws ? "AWS" : "Azure"} Security Findings (${filteredFindings.length})`}
        subtitle="Click any finding row to inspect expected vs. observed evidence in the slide-over drawer"
        action={
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-2 h-3.5 w-3.5 text-[#64748B]" />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Filter rule, resource, region..."
                aria-label={`Search ${provider.toUpperCase()} findings`}
                className="w-52 rounded-[8px] border border-[#243142] bg-[#080D14] py-1.5 pl-8 pr-2.5 text-xs text-[#F1F5F9] placeholder:text-[#64748B] focus:border-[#00D6A0] focus:outline-none"
              />
            </div>
            <select
              aria-label="Filter severity"
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="rounded-[8px] border border-[#243142] bg-[#080D14] px-2.5 py-1.5 text-xs text-[#F1F5F9] focus:border-[#00D6A0] focus:outline-none"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
        }
        noPadding
      >
        {filteredFindings.length === 0 ? (
          <div className="p-5">
            <EmptyState
              title={`No Matching ${isAws ? "AWS" : "Azure"} Findings`}
              description="Adjust filters or run a posture assessment to evaluate rules against this environment."
            />
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-[#243142] bg-[#0C121B] text-[11px] font-semibold uppercase tracking-wider text-[#64748B]">
                <tr>
                  <th className="px-5 py-3">Rule &amp; Resource</th>
                  <th className="px-3 py-3">Region</th>
                  <th className="px-3 py-3">Severity</th>
                  <th className="px-3 py-3">Risk</th>
                  <th className="px-3 py-3">Status</th>
                  <th className="px-5 py-3">Source</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#243142]">
                {filteredFindings.map((f) => (
                  <tr
                    key={f.id}
                    onClick={() => setSelectedFindingId(f.id)}
                    className="cursor-pointer transition-colors hover:bg-[#1C293A]/60"
                  >
                    <td className="px-5 py-3">
                      <div className="font-semibold text-[#F1F5F9]">
                        <span className="mr-2 font-mono text-[#00D6A0]">
                          {f.rule_id}
                        </span>
                        {f.title}
                      </div>
                      <div className="mt-0.5 max-w-md truncate font-mono text-[11px] text-[#64748B]">
                        {f.resource_id}
                      </div>
                    </td>
                    <td className="px-3 py-3 font-mono text-[11px] text-[#A0AEC0]">
                      {f.region}
                    </td>
                    <td className="px-3 py-3">
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td className="px-3 py-3">
                      <RiskScoreBar score={f.risk_score} />
                    </td>
                    <td className="px-3 py-3">
                      <StatusBadge status={f.status} />
                    </td>
                    <td className="px-5 py-3">
                      <DataSourceBadge source={f.data_source} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {/* Assessment Runs & Threat Detections Row */}
      <div className="grid gap-5 lg:grid-cols-2">
        <Panel
          title={`Recent ${isAws ? "AWS" : "Azure"} Assessment Runs`}
          subtitle="Execution pass/fail/not-assessed telemetry"
          action={
            <Link
              to="/assessments"
              className="text-xs font-medium text-[#00D6A0] hover:underline"
            >
              All runs →
            </Link>
          }
        >
          {providerRuns.length === 0 ? (
            <EmptyState
              title="No Assessment Runs Recorded"
              description={`Trigger a read-only ${isAws ? "AWS" : "Azure"} assessment above to capture a baseline snapshot.`}
            />
          ) : (
            <div className="space-y-2.5">
              {providerRuns.slice(0, 5).map((r) => (
                <div
                  key={r.id}
                  className="flex flex-wrap items-center justify-between gap-2 rounded-[10px] border border-[#243142] bg-[#172131]/65 px-3.5 py-2.5 text-xs"
                >
                  <div className="flex items-center gap-2">
                    <StatusBadge status={r.status} />
                    <DataSourceBadge source={r.data_source} />
                    <span className="font-mono text-[11px] text-[#A0AEC0]">
                      {r.assets_discovered} assets
                    </span>
                  </div>
                  <div className="font-mono text-[11px] tabular-nums">
                    <span className="text-[#10B981]">{r.checks_passed} PASS</span>
                    <span className="mx-1.5 text-[#64748B]">·</span>
                    <span className="text-[#F43F5E]">{r.checks_failed} FAIL</span>
                    <span className="mx-1.5 text-[#64748B]">·</span>
                    <span className="text-[#64748B]">
                      {r.started_at.slice(0, 19).replace("T", " ")}Z
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel
          title={
            isAws
              ? "AWS CloudTrail Detections"
              : "Azure Activity Log Detections"
          }
          subtitle="Correlated suspicious API activity mapped to MITRE ATT&CK"
          action={
            <Link
              to="/detections"
              className="text-xs font-medium text-[#00D6A0] hover:underline"
            >
              Detection console →
            </Link>
          }
        >
          {providerDetections.length === 0 ? (
            <EmptyState
              title={`No ${isAws ? "CloudTrail" : "Activity Log"} Detections`}
              description="No suspicious control-plane activity detections recorded for this cloud provider."
            />
          ) : (
            <div className="space-y-2.5">
              {providerDetections.slice(0, 5).map((det) => (
                <div
                  key={det.id}
                  className="rounded-[10px] border border-[#243142] bg-[#172131]/65 p-3 text-xs space-y-1.5"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={det.severity} />
                      <span className="font-semibold text-[#F1F5F9]">
                        {det.title}
                      </span>
                    </div>
                    <span className="rounded-md border border-[#243142] bg-[#080D14] px-2 py-0.5 font-mono text-[10px] text-[#A0AEC0]">
                      {det.mitre_technique}
                    </span>
                  </div>
                  <div className="font-mono text-[11px] text-[#64748B]">
                    Actor: <span className="text-[#A0AEC0]">{det.actor_identity}</span> · Event:{" "}
                    <span className="text-[#A0AEC0]">{det.event_name}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>

      <FindingDetailsDrawer
        findingId={selectedFindingId}
        canPreviewRemediation={canPreviewRemediation}
        onClose={() => setSelectedFindingId(null)}
      />
    </div>
  );
}
