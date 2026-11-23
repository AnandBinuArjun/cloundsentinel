import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  Filter,
  RotateCcw,
  Search,
} from "lucide-react";
import { fetchAuthMe, fetchFindings } from "../lib/api";
import {
  DataSourceBadge,
  ProviderBadge,
  RiskScoreBar,
  SeverityBadge,
  StatusBadge,
} from "../components/Badges";
import { FindingDetailsDrawer } from "../components/FindingDetailsDrawer";
import { EmptyState, ErrorBanner, LoadingState, PageHeader, Panel } from "../components/UI";

const PAGE_SIZE = 12;
const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

export function FindingsPage() {
  const [provider, setProvider] = useState("");
  const [severity, setSeverity] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [search, setSearch] = useState("");
  const [sortBy, setSortBy] = useState<"risk_score" | "severity" | "provider">("risk_score");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [page, setPage] = useState(1);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);

  const authQuery = useQuery({
    queryKey: ["auth-me"],
    queryFn: fetchAuthMe,
    retry: false,
  });

  const query = useQuery({
    queryKey: ["findings", provider, severity, statusFilter, search],
    queryFn: () =>
      fetchFindings({
        provider: provider || undefined,
        severity: severity || undefined,
        status: statusFilter || undefined,
        search: search || undefined,
      }),
    retry: false,
  });

  const canPreviewRemediation = Boolean(
    authQuery.data?.permissions.includes("remediations:preview")
  );

  const items = query.data?.items ?? [];

  const counts = useMemo(() => {
    const out = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of items) {
      const k = f.severity.toLowerCase();
      if (k in out) out[k as keyof typeof out] += 1;
    }
    return out;
  }, [items]);

  const sorted = useMemo(() => {
    const copy = [...items];
    copy.sort((a, b) => {
      let cmp = 0;
      if (sortBy === "risk_score") cmp = a.risk_score - b.risk_score;
      else if (sortBy === "severity")
        cmp =
          (SEVERITY_RANK[a.severity.toLowerCase()] ?? 0) -
          (SEVERITY_RANK[b.severity.toLowerCase()] ?? 0);
      else cmp = a.provider.localeCompare(b.provider);
      return sortDir === "asc" ? cmp : -cmp;
    });
    return copy;
  }, [items, sortBy, sortDir]);

  const totalPages = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages);
  const pageItems = sorted.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);

  const toggleSort = (col: "risk_score" | "severity" | "provider") => {
    if (sortBy === col) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortBy(col);
      setSortDir("desc");
    }
  };

  const hasFilters = Boolean(provider || severity || statusFilter || search);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Posture Triage & Prioritization"
        title="Security Findings"
        description="Deterministic cloud misconfigurations ranked by transparent risk score (0–100). Click any row to open the evidence drawer or open the full investigation view."
        actions={
          <div className="flex flex-wrap items-center gap-1.5 font-mono text-[11px] tabular-nums">
            <button
              type="button"
              onClick={() => {
                setSeverity(severity === "critical" ? "" : "critical");
                setPage(1);
              }}
              className={`rounded-md border px-2.5 py-1 transition-colors ${
                severity === "critical"
                  ? "border-[#F43F5E] bg-[#F43F5E]/20 text-[#F43F5E]"
                  : "border-[#F43F5E]/30 bg-[#F43F5E]/10 text-[#F43F5E]"
              }`}
            >
              Crit {counts.critical}
            </button>
            <button
              type="button"
              onClick={() => {
                setSeverity(severity === "high" ? "" : "high");
                setPage(1);
              }}
              className={`rounded-md border px-2.5 py-1 transition-colors ${
                severity === "high"
                  ? "border-[#F97316] bg-[#F97316]/20 text-[#F97316]"
                  : "border-[#F97316]/30 bg-[#F97316]/10 text-[#F97316]"
              }`}
            >
              High {counts.high}
            </button>
            <button
              type="button"
              onClick={() => {
                setSeverity(severity === "medium" ? "" : "medium");
                setPage(1);
              }}
              className={`rounded-md border px-2.5 py-1 transition-colors ${
                severity === "medium"
                  ? "border-[#F59E0B] bg-[#F59E0B]/20 text-[#F59E0B]"
                  : "border-[#F59E0B]/30 bg-[#F59E0B]/10 text-[#F59E0B]"
              }`}
            >
              Med {counts.medium}
            </button>
            <button
              type="button"
              onClick={() => {
                setSeverity(severity === "low" ? "" : "low");
                setPage(1);
              }}
              className={`rounded-md border px-2.5 py-1 transition-colors ${
                severity === "low"
                  ? "border-[#38BDF8] bg-[#38BDF8]/20 text-[#38BDF8]"
                  : "border-[#38BDF8]/30 bg-[#38BDF8]/10 text-[#38BDF8]"
              }`}
            >
              Low {counts.low}
            </button>
          </div>
        }
      />

      <div className="flex flex-wrap items-center gap-2.5 rounded-[12px] border border-[#243142] bg-[#111925] p-3.5">
        <div className="relative flex-1 min-w-[220px]">
          <Search className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5 text-[#64748B]" />
          <input
            placeholder="Search rule ID, title, or resource ARN/ID..."
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
            className="w-full rounded-[8px] border border-[#243142] bg-[#080D14] py-2 pl-9 pr-3 text-xs text-[#F1F5F9] placeholder:text-[#64748B] focus:border-[#00D6A0] focus:outline-none"
          />
        </div>
        <Filter className="h-3.5 w-3.5 text-[#64748B]" aria-hidden="true" />
        <select
          aria-label="Provider filter"
          value={provider}
          onChange={(e) => {
            setProvider(e.target.value);
            setPage(1);
          }}
          className="rounded-[8px] border border-[#243142] bg-[#080D14] px-3 py-2 text-xs text-[#F1F5F9] focus:border-[#00D6A0] focus:outline-none"
        >
          <option value="">All Providers</option>
          <option value="aws">AWS</option>
          <option value="azure">Azure</option>
        </select>
        <select
          aria-label="Severity filter"
          value={severity}
          onChange={(e) => {
            setSeverity(e.target.value);
            setPage(1);
          }}
          className="rounded-[8px] border border-[#243142] bg-[#080D14] px-3 py-2 text-xs text-[#F1F5F9] focus:border-[#00D6A0] focus:outline-none"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select
          aria-label="Status filter"
          value={statusFilter}
          onChange={(e) => {
            setStatusFilter(e.target.value);
            setPage(1);
          }}
          className="rounded-[8px] border border-[#243142] bg-[#080D14] px-3 py-2 text-xs text-[#F1F5F9] focus:border-[#00D6A0] focus:outline-none"
        >
          <option value="">All Statuses</option>
          <option value="open">Open</option>
          <option value="resolved">Resolved</option>
          <option value="risk_accepted">Risk Accepted</option>
          <option value="false_positive">False Positive</option>
        </select>
        {hasFilters && (
          <button
            type="button"
            onClick={() => {
              setProvider("");
              setSeverity("");
              setStatusFilter("");
              setSearch("");
              setPage(1);
            }}
            className="inline-flex items-center gap-1 rounded-[8px] border border-[#243142] bg-[#172131] px-2.5 py-2 text-xs text-[#A0AEC0] hover:text-[#F1F5F9]"
          >
            <RotateCcw className="h-3 w-3" />
            <span>Reset</span>
          </button>
        )}
      </div>

      <Panel
        title={`Findings (${query.data?.total ?? 0})`}
        subtitle="Click any finding row to inspect evidence in the drawer, or open full investigation page"
        noPadding
      >
        {query.isPending && (
          <div className="p-5">
            <LoadingState label="Querying tenant findings..." />
          </div>
        )}
        {query.isError && (
          <div className="p-5">
            <ErrorBanner message={query.error.message} />
          </div>
        )}
        {query.data && sorted.length === 0 && (
          <div className="p-5">
            <EmptyState
              title="No Matching Findings"
              description="No findings match the active filters, or no posture assessments have been executed yet."
            />
          </div>
        )}
        {query.data && sorted.length > 0 && (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-[#243142] bg-[#0C121B] text-[11px] font-semibold uppercase tracking-wider text-[#64748B]">
                  <tr>
                    <th className="px-5 py-3">Rule &amp; Affected Resource</th>
                    <th className="px-3 py-3">
                      <button
                        type="button"
                        onClick={() => toggleSort("provider")}
                        className="inline-flex items-center gap-1 hover:text-[#F1F5F9]"
                      >
                        Cloud <ArrowUpDown className="h-3 w-3" />
                      </button>
                    </th>
                    <th className="px-3 py-3">
                      <button
                        type="button"
                        onClick={() => toggleSort("severity")}
                        className="inline-flex items-center gap-1 hover:text-[#F1F5F9]"
                      >
                        Severity <ArrowUpDown className="h-3 w-3" />
                      </button>
                    </th>
                    <th className="px-3 py-3">
                      <button
                        type="button"
                        onClick={() => toggleSort("risk_score")}
                        className="inline-flex items-center gap-1 hover:text-[#F1F5F9]"
                      >
                        Risk Score <ArrowUpDown className="h-3 w-3" />
                      </button>
                    </th>
                    <th className="px-3 py-3">Status</th>
                    <th className="px-3 py-3">Source</th>
                    <th className="px-5 py-3 text-right">Detail</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#243142]">
                  {pageItems.map((f) => (
                    <tr
                      key={f.id}
                      onClick={() => setSelectedFindingId(f.id)}
                      className="cursor-pointer transition-colors hover:bg-[#1C293A]/60"
                    >
                      <td className="px-5 py-3">
                        <div className="font-semibold text-[#F1F5F9]">
                          <span className="mr-2 font-mono text-[#00D6A0]">{f.rule_id}</span>
                          {f.title}
                        </div>
                        <div className="mt-0.5 max-w-lg truncate font-mono text-[11px] text-[#64748B]">
                          {f.resource_id}
                        </div>
                      </td>
                      <td className="px-3 py-3">
                        <ProviderBadge provider={f.provider} />
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
                      <td className="px-3 py-3">
                        <DataSourceBadge source={f.data_source} />
                      </td>
                      <td
                        className="px-5 py-3 text-right"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <Link
                          to={`/findings/${f.id}`}
                          className="inline-flex items-center gap-1 rounded-[8px] border border-[#243142] bg-[#172131] px-2.5 py-1 text-[11px] font-medium text-[#A0AEC0] hover:border-[#00D6A0]/40 hover:text-[#00D6A0]"
                        >
                          <span>Open</span>
                          <ExternalLink className="h-3 w-3" />
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {totalPages > 1 && (
              <div className="flex items-center justify-between border-t border-[#243142] bg-[#0C121B] px-5 py-3 text-xs text-[#A0AEC0]">
                <span className="font-mono tabular-nums">
                  Page {safePage} of {totalPages} ({sorted.length} findings)
                </span>
                <div className="flex items-center gap-1.5">
                  <button
                    type="button"
                    disabled={safePage <= 1}
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                    className="inline-flex items-center gap-1 rounded-[8px] border border-[#243142] bg-[#172131] px-2.5 py-1 text-xs text-[#F1F5F9] hover:bg-[#1C293A] disabled:opacity-40"
                  >
                    <ChevronLeft className="h-3.5 w-3.5" />
                    Prev
                  </button>
                  <button
                    type="button"
                    disabled={safePage >= totalPages}
                    onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                    className="inline-flex items-center gap-1 rounded-[8px] border border-[#243142] bg-[#172131] px-2.5 py-1 text-xs text-[#F1F5F9] hover:bg-[#1C293A] disabled:opacity-40"
                  >
                    Next
                    <ChevronRight className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </Panel>

      <FindingDetailsDrawer
        findingId={selectedFindingId}
        canPreviewRemediation={canPreviewRemediation}
        onClose={() => setSelectedFindingId(null)}
      />
    </div>
  );
}
