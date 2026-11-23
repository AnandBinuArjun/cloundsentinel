import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import {
  AlertTriangle,
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  Cloud,
  Database,
  Eye,
  FileCheck2,
  Flame,
  Play,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
} from "lucide-react";
import {
  fetchAuthMe,
  fetchConnections,
  fetchDashboardSummary,
  fetchDetections,
  fetchFindings,
  triggerAssessment,
} from "../lib/api";
import {
  ConnectorStatus,
  DataSourceBadge,
  ProviderBadge,
  RiskScoreBar,
  SeverityBadge,
  StatusBadge,
} from "../components/Badges";
import { ComplianceProgress } from "../components/ComplianceProgress";
import { FindingDetailsDrawer } from "../components/FindingDetailsDrawer";
import { MetricCard } from "../components/MetricCard";
import { EmptyState, ErrorBanner, LoadingState, PageHeader, Panel } from "../components/UI";

const SEVERITY_COLORS: Record<string, string> = {
  Critical: "#F43F5E",
  High: "#F97316",
  Medium: "#F59E0B",
  Low: "#38BDF8",
};

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

const PAGE_SIZE = 6;

export function DashboardPage({ provider }: { provider?: "aws" | "azure" }) {
  const queryClient = useQueryClient();

  const [envFilter, setEnvFilter] = useState<"all" | "aws" | "azure">(provider ?? "all");
  const [dateRange, setDateRange] = useState<"all" | "7d" | "30d">("all");
  const [runPickerOpen, setRunPickerOpen] = useState(false);
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);

  useEffect(() => {
    if (!runPickerOpen) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") setRunPickerOpen(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [runPickerOpen]);

  // Findings table controls
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [sortBy, setSortBy] = useState<"risk" | "severity" | "first_seen">("risk");
  const [sortAsc, setSortAsc] = useState(false);
  const [page, setPage] = useState(0);
  const [selectedIds, setSelectedIds] = useState<Record<string, boolean>>({});
  const [drawerFindingId, setDrawerFindingId] = useState<string | null>(null);

  const effectiveProvider = provider ?? (envFilter === "all" ? undefined : envFilter);

  const meQuery = useQuery({ queryKey: ["auth-me"], queryFn: fetchAuthMe, retry: false });
  const summaryQuery = useQuery({
    queryKey: ["dashboard-summary", effectiveProvider ?? "all"],
    queryFn: () => fetchDashboardSummary(effectiveProvider),
    retry: false,
  });
  const connectionsQuery = useQuery({
    queryKey: ["overview-connections", effectiveProvider ?? "all"],
    queryFn: () => fetchConnections(effectiveProvider),
    retry: false,
  });
  const findingsQuery = useQuery({
    queryKey: ["overview-findings", effectiveProvider ?? "all"],
    queryFn: () => fetchFindings({ provider: effectiveProvider }),
    retry: false,
  });
  const detectionsQuery = useQuery({
    queryKey: ["overview-detections"],
    queryFn: fetchDetections,
    retry: false,
  });

  const runAssessMut = useMutation({
    mutationFn: triggerAssessment,
    onSuccess: (run) => {
      setRunPickerOpen(false);
      setActionFeedback(
        `Assessment completed (${run.provider.toUpperCase()}): ${run.checks_passed} PASS, ${run.checks_failed} FAIL.`
      );
      void queryClient.invalidateQueries();
    },
    onError: (err: Error) => setActionFeedback(`Assessment failed: ${err.message}`),
  });

  const canRunAssessment = Boolean(meQuery.data?.permissions.includes("assessments:run"));
  const canPreviewRemediation = Boolean(
    meQuery.data?.permissions.includes("remediations:preview")
  );

  // Apply date-range + table search/filter/sort on real findings
  const processedFindings = useMemo(() => {
    const items = findingsQuery.data?.items ?? [];
    const now = Date.now();
    const cutoff =
      dateRange === "7d"
        ? now - 7 * 86400 * 1000
        : dateRange === "30d"
          ? now - 30 * 86400 * 1000
          : 0;

    const q = search.trim().toLowerCase();
    const filtered = items.filter((f) => {
      if (cutoff && new Date(f.last_seen_at).getTime() < cutoff) return false;
      if (severityFilter && f.severity.toLowerCase() !== severityFilter) return false;
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

    filtered.sort((a, b) => {
      let cmp = 0;
      if (sortBy === "risk") {
        cmp = a.risk_score - b.risk_score;
      } else if (sortBy === "severity") {
        cmp = (SEVERITY_RANK[a.severity] ?? 0) - (SEVERITY_RANK[b.severity] ?? 0);
      } else {
        cmp = new Date(a.first_seen_at).getTime() - new Date(b.first_seen_at).getTime();
      }
      return sortAsc ? cmp : -cmp;
    });
    return filtered;
  }, [findingsQuery.data, dateRange, search, severityFilter, sortBy, sortAsc]);

  const totalPages = Math.max(1, Math.ceil(processedFindings.length / PAGE_SIZE));
  const pagedFindings = processedFindings.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  // Derived Risk Intelligence from real findings (never fabricated)
  const riskIntelligence = useMemo(() => {
    const openItems = (findingsQuery.data?.items ?? []).filter((f) => f.status === "open");
    const byProvider = { aws: { count: 0, critHigh: 0 }, azure: { count: 0, critHigh: 0 } };
    const byCategory = new Map<string, number>();

    for (const f of openItems) {
      if (f.provider === "aws") {
        byProvider.aws.count += 1;
        if (f.severity === "critical" || f.severity === "high") byProvider.aws.critHigh += 1;
      } else if (f.provider === "azure") {
        byProvider.azure.count += 1;
        if (f.severity === "critical" || f.severity === "high") byProvider.azure.critHigh += 1;
      }
      byCategory.set(f.resource_type, (byCategory.get(f.resource_type) ?? 0) + 1);
    }

    const topCategories = Array.from(byCategory.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);

    const topPriority = [...openItems].sort((a, b) => b.risk_score - a.risk_score).slice(0, 4);
    return { byProvider, topCategories, topPriority };
  }, [findingsQuery.data]);

  const filteredDetections = useMemo(() => {
    const items = detectionsQuery.data?.items ?? [];
    return effectiveProvider ? items.filter((d) => d.provider === effectiveProvider) : items;
  }, [detectionsQuery.data, effectiveProvider]);

  const handleSort = (column: "risk" | "severity" | "first_seen") => {
    if (sortBy === column) {
      setSortAsc((prev) => !prev);
    } else {
      setSortBy(column);
      setSortAsc(false);
    }
    setPage(0);
  };

  const handleRefreshAll = () => {
    setActionFeedback(null);
    void queryClient.invalidateQueries();
  };

  const title =
    provider === "aws"
      ? "AWS Security Workspace"
      : provider === "azure"
        ? "Azure Security Workspace"
        : "Security Overview";

  const subtitle =
    provider === "aws"
      ? "AWS account posture, IAM exposure, and deterministic read-only checks."
      : provider === "azure"
        ? "Azure subscription posture, RBAC analysis, and storage/network security."
        : "Unified visibility across your connected cloud environments.";

  if (summaryQuery.isPending) {
    return (
      <div className="space-y-6">
        <PageHeader eyebrow="Security Intelligence Workspace" title={title} description={subtitle} />
        <LoadingState label="Synchronizing multi-cloud posture, detections, and compliance telemetry..." />
      </div>
    );
  }

  if (summaryQuery.isError) {
    return (
      <div className="space-y-5">
        <PageHeader eyebrow="Security Intelligence Workspace" title={title} description={subtitle} />
        <ErrorBanner
          message={`Unable to load security overview: ${summaryQuery.error.message}. Authenticate at /login with a valid OIDC or local dev JWT.`}
        />
      </div>
    );
  }

  const data = summaryQuery.data;
  const assessedFrameworks = data.compliance_summary.filter(
    (fw) => fw.technical_pass_rate_pct !== null
  );
  const avgCompliancePct =
    assessedFrameworks.length > 0
      ? `${(
          assessedFrameworks.reduce((acc, fw) => acc + (fw.technical_pass_rate_pct ?? 0), 0) /
          assessedFrameworks.length
        ).toFixed(1)}%`
      : "Not Assessed";

  const severityChartData = [
    { name: "Critical", count: data.findings.by_severity.critical },
    { name: "High", count: data.findings.by_severity.high },
    { name: "Medium", count: data.findings.by_severity.medium },
    { name: "Low", count: data.findings.by_severity.low },
  ];

  const connections = connectionsQuery.data?.items ?? [];
  const awsConnections = connections.filter((c) => c.provider === "aws");
  const azureConnections = connections.filter((c) => c.provider === "azure");

  const updatedTime = summaryQuery.dataUpdatedAt
    ? new Date(summaryQuery.dataUpdatedAt).toISOString().slice(11, 16) + "Z"
    : undefined;

  return (
    <div className="space-y-6">
      {/* A. Page Heading & Operational Controls */}
      <PageHeader
        eyebrow="Security Intelligence Workspace"
        title={title}
        description={subtitle}
        actions={
          <>
            {!provider && (
              <select
                aria-label="Environment selector"
                value={envFilter}
                onChange={(e) => {
                  setEnvFilter(e.target.value as "all" | "aws" | "azure");
                  setPage(0);
                }}
                className="rounded-[8px] border border-[#243142] bg-[#111925] px-3 py-2 text-xs font-medium text-[#F1F5F9] focus:border-[#00D6A0] focus:outline-none"
              >
                <option value="all">All Environments</option>
                <option value="aws">AWS Only</option>
                <option value="azure">Azure Only</option>
              </select>
            )}

            <select
              aria-label="Assessment date range"
              value={dateRange}
              onChange={(e) => {
                setDateRange(e.target.value as "all" | "7d" | "30d");
                setPage(0);
              }}
              className="rounded-[8px] border border-[#243142] bg-[#111925] px-3 py-2 text-xs font-medium text-[#F1F5F9] focus:border-[#00D6A0] focus:outline-none"
            >
              <option value="all">All Time</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
            </select>

            <button
              type="button"
              onClick={handleRefreshAll}
              className="inline-flex items-center gap-1.5 rounded-[8px] border border-[#243142] bg-[#111925] px-3 py-2 text-xs font-medium text-[#A0AEC0] hover:bg-[#1C293A] hover:text-[#F1F5F9]"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${summaryQuery.isFetching ? "animate-spin" : ""}`} />
              <span>Refresh</span>
            </button>

            <div className="relative">
              <button
                type="button"
                disabled={!canRunAssessment || connections.length === 0 || runAssessMut.isPending}
                title={
                  !canRunAssessment
                    ? "Requires assessments:run permission"
                    : connections.length === 0
                      ? "Register a cloud connection first"
                      : "Trigger read-only posture assessment"
                }
                onClick={() => setRunPickerOpen((p) => !p)}
                className="inline-flex items-center gap-1.5 rounded-[8px] border border-[#00D6A0]/45 bg-[#00D6A0]/15 px-3.5 py-2 text-xs font-semibold text-[#00D6A0] hover:bg-[#00D6A0]/25 disabled:cursor-not-allowed disabled:opacity-45"
              >
                <Play className="h-3.5 w-3.5" />
                <span>{runAssessMut.isPending ? "Running..." : "Run Assessment"}</span>
              </button>

              {runPickerOpen && connections.length > 0 && (
                <>
                  <div
                    className="fixed inset-0 z-20"
                    onClick={() => setRunPickerOpen(false)}
                    aria-hidden="true"
                  />
                  <div className="absolute right-0 z-30 mt-2 w-72 rounded-[12px] border border-[#243142] bg-[#111925] p-2 shadow-2xl">
                    <div className="border-b border-[#243142] px-2.5 py-1.5 text-[11px] font-semibold text-[#F1F5F9]">
                      Select Target Environment
                    </div>
                    <div className="mt-1 space-y-1">
                      {connections.map((c) => (
                        <button
                          key={c.id}
                          type="button"
                          onClick={() => runAssessMut.mutate(c.id)}
                          className="flex w-full items-center justify-between rounded-[8px] px-2.5 py-2 text-left text-xs text-[#F1F5F9] hover:bg-[#1C293A]"
                        >
                          <span className="truncate pr-2 font-medium">{c.name}</span>
                          <ProviderBadge provider={c.provider} />
                        </button>
                      ))}
                    </div>
                  </div>
                </>
              )}
            </div>
          </>
        }
      />

      {/* Provenance Banner (Mandatory Security UX) */}
      {data.contains_synthetic_fixtures && (
        <div className="flex flex-wrap items-center justify-between gap-2 rounded-[12px] border border-[#F59E0B]/35 bg-[#F59E0B]/10 px-4 py-2.5 text-xs text-[#F1F5F9]">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 shrink-0 text-[#F59E0B]" />
            <span>
              This workspace includes <strong>synthetic demonstration fixtures</strong>. Live and
              synthetic records are explicitly labeled by <code>data_source</code>.
            </span>
          </div>
          <div className="flex items-center gap-1.5">
            {data.data_sources.map((src) => (
              <DataSourceBadge key={src} source={src} />
            ))}
          </div>
        </div>
      )}

      {actionFeedback && (
        <div className="rounded-[12px] border border-[#00D6A0]/35 bg-[#00D6A0]/10 px-4 py-2.5 text-xs text-[#F1F5F9]">
          {actionFeedback}
        </div>
      )}

      {/* B. Compact 6-Card KPI Summary Grid */}
      <section aria-label="Security Summary" className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
        <MetricCard
          label="Cloud Environments"
          value={data.connections.total}
          sublabel={`AWS ${data.connections.aws} · Azure ${data.connections.azure}`}
          icon={<Cloud className="h-4 w-4" />}
          to="/connections"
          accent="info"
          updatedAt={updatedTime}
        />
        <MetricCard
          label="Discovered Assets"
          value={data.cloud_inventory.total_assets}
          sublabel="Normalized inventory"
          icon={<Database className="h-4 w-4" />}
          to="/assets"
          updatedAt={updatedTime}
        />
        <MetricCard
          label="Open Findings"
          value={data.findings.open}
          sublabel={`${data.findings.resolved} resolved · ${data.findings.risk_accepted} accepted`}
          icon={<ShieldAlert className="h-4 w-4" />}
          to="/findings"
          accent="high"
        />
        <MetricCard
          label="Critical Risks"
          value={data.findings.by_severity.critical}
          sublabel={`${data.findings.by_severity.high} high severity`}
          icon={<Flame className="h-4 w-4" />}
          to="/findings"
          accent="critical"
        />
        <MetricCard
          label="Active Detections"
          value={data.detections.open}
          sublabel={`${data.detections.critical} critical alerts`}
          icon={<Shield className="h-4 w-4" />}
          to="/detections"
          accent={data.detections.critical > 0 ? "critical" : "default"}
        />
        <MetricCard
          label="Compliance Coverage"
          value={avgCompliancePct}
          sublabel="Technical checks avg"
          icon={<FileCheck2 className="h-4 w-4" />}
          to="/compliance"
          accent="success"
        />
      </section>

      {/* C. Cloud Security Posture (AWS vs Azure) */}
      <section aria-label="Cloud Security Posture" className="grid gap-4 lg:grid-cols-2">
        <Panel
          title="AWS Cloud Posture"
          subtitle="Cross-account STS read-only assessments"
          action={
            <div className="flex items-center gap-2">
              <ProviderBadge provider="aws" />
              <Link to="/aws" className="text-xs font-medium text-[#00D6A0] hover:underline">
                Workspace →
              </Link>
            </div>
          }
        >
          <div className="grid grid-cols-3 gap-3 text-xs">
            <div className="rounded-[8px] border border-[#243142] bg-[#172131] p-3">
              <div className="text-[11px] text-[#64748B]">Accounts</div>
              <div className="mt-1 font-mono text-lg font-semibold text-[#F1F5F9] tabular-nums">
                {data.cloud_inventory.aws_accounts}
              </div>
            </div>
            <div className="rounded-[8px] border border-[#243142] bg-[#172131] p-3">
              <div className="text-[11px] text-[#64748B]">Open Findings</div>
              <div className="mt-1 font-mono text-lg font-semibold text-[#F1F5F9] tabular-nums">
                {riskIntelligence.byProvider.aws.count}
              </div>
            </div>
            <div className="rounded-[8px] border border-[#243142] bg-[#172131] p-3">
              <div className="text-[11px] text-[#64748B]">Crit / High</div>
              <div className="mt-1 font-mono text-lg font-semibold text-[#F97316] tabular-nums">
                {riskIntelligence.byProvider.aws.critHigh}
              </div>
            </div>
          </div>
          <div className="mt-3.5 flex items-center justify-between text-xs">
            <ConnectorStatus
              healthy={awsConnections.filter((c) => c.status === "healthy").length}
              total={awsConnections.length}
            />
            <span className="font-mono text-[11px] text-[#64748B]">
              10 deterministic rules active
            </span>
          </div>
        </Panel>

        <Panel
          title="Microsoft Azure Posture"
          subtitle="Managed / Workload Identity ARM assessments"
          action={
            <div className="flex items-center gap-2">
              <ProviderBadge provider="azure" />
              <Link to="/azure" className="text-xs font-medium text-[#00D6A0] hover:underline">
                Workspace →
              </Link>
            </div>
          }
        >
          <div className="grid grid-cols-3 gap-3 text-xs">
            <div className="rounded-[8px] border border-[#243142] bg-[#172131] p-3">
              <div className="text-[11px] text-[#64748B]">Subscriptions</div>
              <div className="mt-1 font-mono text-lg font-semibold text-[#F1F5F9] tabular-nums">
                {data.cloud_inventory.azure_subscriptions}
              </div>
            </div>
            <div className="rounded-[8px] border border-[#243142] bg-[#172131] p-3">
              <div className="text-[11px] text-[#64748B]">Open Findings</div>
              <div className="mt-1 font-mono text-lg font-semibold text-[#F1F5F9] tabular-nums">
                {riskIntelligence.byProvider.azure.count}
              </div>
            </div>
            <div className="rounded-[8px] border border-[#243142] bg-[#172131] p-3">
              <div className="text-[11px] text-[#64748B]">Crit / High</div>
              <div className="mt-1 font-mono text-lg font-semibold text-[#F97316] tabular-nums">
                {riskIntelligence.byProvider.azure.critHigh}
              </div>
            </div>
          </div>
          <div className="mt-3.5 flex items-center justify-between text-xs">
            <ConnectorStatus
              healthy={azureConnections.filter((c) => c.status === "healthy").length}
              total={azureConnections.length}
            />
            <span className="font-mono text-[11px] text-[#64748B]">
              8 deterministic rules active
            </span>
          </div>
        </Panel>
      </section>

      {/* D. Risk Intelligence */}
      <section aria-label="Risk Intelligence" className="grid gap-4 lg:grid-cols-3">
        <Panel title="Findings by Severity" subtitle="Active deduplicated open findings">
          {data.findings.open === 0 ? (
            <EmptyState
              title="No Open Findings"
              description="Run an assessment to visualize severity distribution."
            />
          ) : (
            <div className="h-52 min-w-0">
              <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={200}>
                <BarChart data={severityChartData} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
                  <XAxis dataKey="name" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} />
                  <YAxis
                    stroke="#64748B"
                    fontSize={11}
                    allowDecimals={false}
                    tickLine={false}
                    axisLine={false}
                  />
                  <Tooltip
                    cursor={{ fill: "rgba(28,41,58,0.45)" }}
                    contentStyle={{
                      backgroundColor: "#172131",
                      borderColor: "#243142",
                      borderRadius: "8px",
                      fontSize: "12px",
                    }}
                  />
                  <Bar dataKey="count" radius={[6, 6, 0, 0]} maxBarSize={44}>
                    {severityChartData.map((entry) => (
                      <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] ?? "#00D6A0"} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </Panel>

        <Panel title="Top Affected Asset Categories" subtitle="Grouped from live open findings">
          {riskIntelligence.topCategories.length === 0 ? (
            <EmptyState
              title="No Categories Flagged"
              description="Asset categories appear once open findings are recorded."
            />
          ) : (
            <div className="space-y-3">
              {riskIntelligence.topCategories.map(([cat, count]) => {
                const maxVal = riskIntelligence.topCategories[0]?.[1] || 1;
                const widthPct = Math.round((count / maxVal) * 100);
                return (
                  <div key={cat} className="space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-mono text-[#F1F5F9]">{cat}</span>
                      <span className="font-mono text-[#A0AEC0] tabular-nums">{count}</span>
                    </div>
                    <div className="h-1.5 w-full overflow-hidden rounded-full bg-[#1C293A]">
                      <div
                        className="h-full rounded-full bg-[#00D6A0]"
                        style={{ width: `${widthPct}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Panel>

        <Panel
          title="Highest-Priority Risks"
          subtitle="Ranked by transparent 0–100 risk engine"
          action={
            <Link to="/findings" className="text-xs font-medium text-[#00D6A0] hover:underline">
              All →
            </Link>
          }
        >
          {riskIntelligence.topPriority.length === 0 ? (
            <EmptyState
              title="Queue Clear"
              description="No open prioritized findings require immediate triage."
            />
          ) : (
            <div className="space-y-2">
              {riskIntelligence.topPriority.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setDrawerFindingId(item.id)}
                  className="flex w-full items-start justify-between gap-2 rounded-[8px] border border-[#243142] bg-[#172131]/75 p-2.5 text-left transition-colors hover:border-[#00D6A0]/40 hover:bg-[#1C293A]"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5">
                      <span className="font-mono text-[11px] font-semibold text-[#00D6A0]">
                        {item.rule_id}
                      </span>
                      <ProviderBadge provider={item.provider} />
                    </div>
                    <div className="mt-1 truncate text-xs font-medium text-[#F1F5F9]">
                      {item.title}
                    </div>
                  </div>
                  <RiskScoreBar score={item.risk_score} />
                </button>
              ))}
            </div>
          )}
        </Panel>
      </section>

      {/* E. Interactive Security Findings Table */}
      <Panel
        title={`Security Findings (${processedFindings.length})`}
        subtitle="Click any row to open the right-side evidence investigation drawer"
        action={
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-2 h-3.5 w-3.5 text-[#64748B]" />
              <input
                aria-label="Filter findings"
                placeholder="Search rule, finding, asset..."
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                  setPage(0);
                }}
                className="w-52 rounded-[8px] border border-[#243142] bg-[#0C121B] py-1.5 pl-8 pr-2.5 text-xs text-[#F1F5F9] placeholder:text-[#64748B] focus:border-[#00D6A0] focus:outline-none"
              />
            </div>
            <select
              aria-label="Filter severity"
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value);
                setPage(0);
              }}
              className="rounded-[8px] border border-[#243142] bg-[#0C121B] px-2.5 py-1.5 text-xs text-[#F1F5F9] focus:border-[#00D6A0] focus:outline-none"
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
        {findingsQuery.isPending ? (
          <div className="p-5">
            <LoadingState label="Loading findings table..." />
          </div>
        ) : pagedFindings.length === 0 ? (
          <div className="p-5">
            <EmptyState
              title="No Findings Match Filters"
              description="Adjust your search or severity filter, or run a new assessment."
            />
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-[#243142] bg-[#172131]/70 font-mono text-[10px] uppercase tracking-wider text-[#64748B]">
                  <tr>
                    <th className="w-9 px-4 py-2.5">
                      <span className="sr-only">Select</span>
                    </th>
                    <th className="px-3 py-2.5">
                      <button
                        type="button"
                        onClick={() => handleSort("severity")}
                        className="inline-flex items-center gap-1 hover:text-[#F1F5F9]"
                      >
                        Severity <ArrowUpDown className="h-3 w-3" />
                      </button>
                    </th>
                    <th className="px-3 py-2.5">Finding</th>
                    <th className="px-3 py-2.5">Affected Asset</th>
                    <th className="px-3 py-2.5">Cloud</th>
                    <th className="px-3 py-2.5">
                      <button
                        type="button"
                        onClick={() => handleSort("risk")}
                        className="inline-flex items-center gap-1 hover:text-[#F1F5F9]"
                      >
                        Risk <ArrowUpDown className="h-3 w-3" />
                      </button>
                    </th>
                    <th className="px-3 py-2.5">
                      <button
                        type="button"
                        onClick={() => handleSort("first_seen")}
                        className="inline-flex items-center gap-1 hover:text-[#F1F5F9]"
                      >
                        First Observed <ArrowUpDown className="h-3 w-3" />
                      </button>
                    </th>
                    <th className="px-3 py-2.5">Status</th>
                    <th className="px-4 py-2.5 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#243142]">
                  {pagedFindings.map((f) => (
                    <tr
                      key={f.id}
                      onClick={() => setDrawerFindingId(f.id)}
                      className="cursor-pointer transition-colors hover:bg-[#1C293A]/70"
                    >
                      <td
                        className="px-4 py-3"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <input
                          type="checkbox"
                          aria-label={`Select ${f.rule_id}`}
                          checked={Boolean(selectedIds[f.id])}
                          onChange={(e) =>
                            setSelectedIds((prev) => ({ ...prev, [f.id]: e.target.checked }))
                          }
                          className="rounded border-[#243142] bg-[#0C121B]"
                        />
                      </td>
                      <td className="px-3 py-3">
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td className="px-3 py-3">
                        <div className="font-semibold text-[#F1F5F9]">{f.title}</div>
                        <div className="font-mono text-[10px] text-[#00D6A0]">{f.rule_id}</div>
                      </td>
                      <td className="max-w-[220px] truncate px-3 py-3 font-mono text-[11px] text-[#A0AEC0]">
                        {f.resource_id}
                      </td>
                      <td className="px-3 py-3">
                        <ProviderBadge provider={f.provider} />
                      </td>
                      <td className="px-3 py-3">
                        <RiskScoreBar score={f.risk_score} />
                      </td>
                      <td className="px-3 py-3 font-mono text-[11px] text-[#64748B]">
                        {f.first_seen_at.slice(0, 10)}
                      </td>
                      <td className="px-3 py-3">
                        <StatusBadge status={f.status} />
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            setDrawerFindingId(f.id);
                          }}
                          className="inline-flex items-center gap-1 rounded-[8px] border border-[#243142] bg-[#172131] px-2.5 py-1 text-[11px] font-medium text-[#F1F5F9] hover:border-[#00D6A0]/40 hover:text-[#00D6A0]"
                        >
                          <Eye className="h-3 w-3" />
                          <span>Inspect</span>
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination footer */}
            <div className="flex items-center justify-between border-t border-[#243142] bg-[#0C121B] px-4 py-2.5 text-xs text-[#64748B]">
              <span className="font-mono">
                Page {page + 1} of {totalPages} ({processedFindings.length} findings)
              </span>
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  disabled={page === 0}
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                  className="inline-flex items-center gap-1 rounded-[8px] border border-[#243142] bg-[#111925] px-2.5 py-1 text-[#A0AEC0] hover:text-[#F1F5F9] disabled:opacity-40"
                >
                  <ChevronLeft className="h-3.5 w-3.5" /> Prev
                </button>
                <button
                  type="button"
                  disabled={page + 1 >= totalPages}
                  onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                  className="inline-flex items-center gap-1 rounded-[8px] border border-[#243142] bg-[#111925] px-2.5 py-1 text-[#A0AEC0] hover:text-[#F1F5F9] disabled:opacity-40"
                >
                  Next <ChevronRight className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          </>
        )}
      </Panel>

      {/* F. Threat Detection Activity & G. Compliance Coverage */}
      <div className="grid gap-5 lg:grid-cols-2">
        <Panel
          title="Threat Detection Activity"
          subtitle="Recent CloudTrail & Azure Activity Log rule matches"
          action={
            <Link to="/detections" className="text-xs font-medium text-[#00D6A0] hover:underline">
              SOC View →
            </Link>
          }
        >
          {detectionsQuery.isPending ? (
            <LoadingState label="Loading threat detections..." />
          ) : filteredDetections.length === 0 ? (
            <EmptyState
              title="No Threat Detections Recorded"
              description="No CloudTrail or Azure Activity Log detection events match the active scope."
            />
          ) : (
            <div className="space-y-2.5">
              {filteredDetections.slice(0, 5).map((det) => (
                <div
                  key={det.id}
                  className="rounded-[8px] border border-[#243142] bg-[#172131]/70 p-3 text-xs space-y-1.5"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-1.5">
                      <SeverityBadge severity={det.severity} />
                      <ProviderBadge provider={det.provider} />
                      <span className="font-mono text-[11px] font-semibold text-[#F1F5F9]">
                        {det.event_name}
                      </span>
                    </div>
                    <StatusBadge status={det.disposition} />
                  </div>
                  <div className="text-[#A0AEC0]">{det.title}</div>
                  <div className="flex flex-wrap items-center justify-between font-mono text-[10px] text-[#64748B]">
                    <span>
                      MITRE {det.mitre_technique} · conf:{det.confidence}
                    </span>
                    <span>{det.event_time.slice(0, 19).replace("T", " ")} UTC</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel
          title="Compliance Technical Control Status"
          subtitle="Automated checks only — never constitutes organizational certification"
          action={
            <Link to="/compliance" className="text-xs font-medium text-[#00D6A0] hover:underline">
              Full Matrix →
            </Link>
          }
        >
          {data.compliance_summary.length === 0 ? (
            <EmptyState
              title="No Compliance Evaluations"
              description="Run an assessment to evaluate CIS, NIST CSF 2.0, and ISO 27001 controls."
            />
          ) : (
            <div className="space-y-3.5">
              {data.compliance_summary.map((fw) => (
                <div
                  key={fw.id}
                  className="rounded-[8px] border border-[#243142] bg-[#172131]/70 p-3.5 space-y-2"
                >
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-[#F1F5F9]">
                      {fw.name} <span className="font-mono text-[#64748B]">v{fw.version}</span>
                    </span>
                    <span className="font-mono font-semibold text-[#00D6A0] tabular-nums">
                      {fw.technical_pass_rate_pct === null
                        ? "NOT ASSESSED"
                        : `${fw.technical_pass_rate_pct}%`}
                    </span>
                  </div>
                  <ComplianceProgress
                    passed={fw.passed}
                    failed={fw.failed}
                    notAssessedOrError={fw.not_assessed_or_error}
                    total={fw.total_controls}
                  />
                  <div className="flex items-center gap-3 font-mono text-[11px] tabular-nums">
                    <span className="text-[#10B981]">Passed {fw.passed}</span>
                    <span className="text-[#F43F5E]">Failed {fw.failed}</span>
                    <span className="text-[#94A3B8]">
                      Not Assessed / Err {fw.not_assessed_or_error}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>

      {/* Right-Side Finding Investigation Drawer */}
      <FindingDetailsDrawer
        findingId={drawerFindingId}
        canPreviewRemediation={canPreviewRemediation}
        onClose={() => setDrawerFindingId(null)}
      />
    </div>
  );
}
