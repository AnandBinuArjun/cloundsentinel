import { Fragment, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, History, Server, ShieldAlert } from "lucide-react";
import { fetchAssessments } from "../lib/api";
import { DataSourceBadge, ProviderBadge, StatusBadge } from "../components/Badges";
import { MetricCard } from "../components/MetricCard";
import { EmptyState, ErrorBanner, LoadingState, PageHeader, Panel } from "../components/UI";

export function AssessmentsPage() {
  const [providerFilter, setProviderFilter] = useState("");
  const [expandedRunId, setExpandedRunId] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ["assessments"],
    queryFn: fetchAssessments,
    retry: false,
  });

  const items = query.data?.items ?? [];
  const filtered = useMemo(
    () =>
      providerFilter
        ? items.filter((r) => r.provider.toLowerCase() === providerFilter)
        : items,
    [items, providerFilter]
  );

  const completedCount = items.filter((r) =>
    r.status.toLowerCase().includes("completed")
  ).length;
  const totalAssets = items.reduce((acc, r) => acc + r.assets_discovered, 0);
  const totalFailedChecks = items.reduce((acc, r) => acc + r.checks_failed, 0);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Audit Trail of Cloud Scans"
        title="Assessment History"
        description="Complete execution log showing discovered assets, PASS/FAIL/NOT_ASSESSED/ERROR counts, provenance, and partial collection warnings."
        actions={
          <select
            aria-label="Filter provider"
            value={providerFilter}
            onChange={(e) => setProviderFilter(e.target.value)}
            className="rounded-[8px] border border-[#243142] bg-[#0C121B] px-3 py-2 text-xs text-[#F1F5F9] focus:border-[#00D6A0] focus:outline-none"
          >
            <option value="">All Providers</option>
            <option value="aws">AWS</option>
            <option value="azure">Azure</option>
          </select>
        }
      />

      <section aria-label="Assessment Summary" className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          label="Total Runs"
          value={items.length}
          subtitle="Recorded scan executions"
          icon={History}
          accent="accent"
        />
        <MetricCard
          label="Completed Runs"
          value={completedCount}
          subtitle="Finished assessment cycles"
          icon={CheckCircle2}
          accent="success"
        />
        <MetricCard
          label="Assets Evaluated"
          value={totalAssets}
          subtitle="Cumulative across runs"
          icon={Server}
          accent="info"
        />
        <MetricCard
          label="Failed Checks"
          value={totalFailedChecks}
          subtitle="Cumulative rule failures"
          icon={ShieldAlert}
          accent={totalFailedChecks > 0 ? "warning" : "success"}
        />
      </section>

      <Panel title={`Assessment Runs (${filtered.length})`} noPadding>
        {query.isPending && (
          <div className="p-5">
            <LoadingState label="Loading assessment history..." />
          </div>
        )}
        {query.isError && (
          <div className="p-5">
            <ErrorBanner message={query.error.message} />
          </div>
        )}
        {query.data && filtered.length === 0 && (
          <div className="p-5">
            <EmptyState
              title="No Assessment Runs Executed"
              description="Go to Cloud Connections to run your first read-only AWS or Azure posture assessment."
            />
          </div>
        )}
        {query.data && filtered.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-[#243142] bg-[#0C121B] text-[11px] font-semibold uppercase tracking-wider text-[#64748B]">
                <tr>
                  <th className="px-5 py-3">Cloud</th>
                  <th className="px-3 py-3">Status</th>
                  <th className="px-3 py-3">Assets</th>
                  <th className="px-3 py-3">PASS / FAIL / NA / ERR</th>
                  <th className="px-3 py-3">Source</th>
                  <th className="px-3 py-3">Started (UTC)</th>
                  <th className="px-5 py-3 text-right">Warnings</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#243142]">
                {filtered.map((r) => {
                  const hasWarnings = r.partial_failures.length > 0;
                  const isOpen = expandedRunId === r.id;
                  return (
                    <Fragment key={r.id}>
                      <tr className="transition-colors hover:bg-[#1C293A]/60">
                        <td className="px-5 py-3">
                          <ProviderBadge provider={r.provider} />
                        </td>
                        <td className="px-3 py-3">
                          <StatusBadge status={r.status} />
                        </td>
                        <td className="px-3 py-3 font-mono tabular-nums text-[#F1F5F9]">
                          {r.assets_discovered}
                        </td>
                        <td className="px-3 py-3 font-mono tabular-nums">
                          <span className="text-[#10B981]">{r.checks_passed}</span>
                          <span className="text-[#64748B]"> / </span>
                          <span className="text-[#F43F5E]">{r.checks_failed}</span>
                          <span className="text-[#64748B]"> / </span>
                          <span className="text-[#F59E0B]">{r.checks_not_assessed}</span>
                          <span className="text-[#64748B]"> / </span>
                          <span className="text-[#A0AEC0]">{r.checks_errored}</span>
                        </td>
                        <td className="px-3 py-3">
                          <DataSourceBadge source={r.data_source} />
                        </td>
                        <td className="px-3 py-3 font-mono text-[11px] text-[#A0AEC0]">
                          {r.started_at.slice(0, 19).replace("T", " ")}Z
                        </td>
                        <td className="px-5 py-3 text-right">
                          {hasWarnings ? (
                            <button
                              type="button"
                              onClick={() => setExpandedRunId(isOpen ? null : r.id)}
                              className="inline-flex items-center gap-1 rounded-md border border-[#F59E0B]/35 bg-[#F59E0B]/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-[#F59E0B]"
                            >
                              <AlertTriangle className="h-3 w-3" />
                              {r.partial_failures.length} partial
                            </button>
                          ) : (
                            <span className="font-mono text-[11px] text-[#64748B]">None</span>
                          )}
                        </td>
                      </tr>
                      {isOpen && hasWarnings && (
                        <tr className="bg-[#080D14]">
                          <td colSpan={7} className="px-5 py-3">
                            <pre className="overflow-x-auto rounded-[8px] border border-[#F59E0B]/30 bg-[#111925] p-3 font-mono text-[11px] text-[#F59E0B]">
                              {JSON.stringify(r.partial_failures, null, 2)}
                            </pre>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
