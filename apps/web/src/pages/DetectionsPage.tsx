import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, AlertTriangle, CheckCircle2, Search, ShieldAlert } from "lucide-react";
import { fetchAuthMe, fetchDetections, updateDetectionDisposition } from "../lib/api";
import {
  DataSourceBadge,
  ProviderBadge,
  SeverityBadge,
  StatusBadge,
} from "../components/Badges";
import { MetricCard } from "../components/MetricCard";
import { EmptyState, ErrorBanner, LoadingState, PageHeader, Panel } from "../components/UI";

export function DetectionsPage() {
  const qc = useQueryClient();
  const [search, setSearch] = useState("");
  const [providerFilter, setProviderFilter] = useState("");
  const [dispositionFilter, setDispositionFilter] = useState("");
  const [feedback, setFeedback] = useState<string | null>(null);

  const authQuery = useQuery({
    queryKey: ["auth-me"],
    queryFn: fetchAuthMe,
    retry: false,
  });

  const query = useQuery({
    queryKey: ["detections"],
    queryFn: fetchDetections,
    retry: false,
  });

  const canTriage = Boolean(
    authQuery.data?.permissions.includes("detections:write") ||
      authQuery.data?.permissions.includes("findings:write")
  );

  const disposeMut = useMutation({
    mutationFn: ({ id, disposition }: { id: string; disposition: string }) =>
      updateDetectionDisposition(id, disposition, `Marked ${disposition} by analyst via console.`),
    onSuccess: (updated) => {
      setFeedback(
        `Detection ${updated.rule_id} updated to ${updated.disposition.replace(/_/g, " ")}.`
      );
      void qc.invalidateQueries({ queryKey: ["detections"] });
      void qc.invalidateQueries({ queryKey: ["dashboard-summary"] });
    },
    onError: (e: Error) => setFeedback(`Disposition error: ${e.message}`),
  });

  const items = query.data?.items ?? [];

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return items.filter((d) => {
      if (providerFilter && d.provider.toLowerCase() !== providerFilter) return false;
      if (dispositionFilter && d.disposition.toLowerCase() !== dispositionFilter) return false;
      if (!q) return true;
      return (
        d.rule_id.toLowerCase().includes(q) ||
        d.title.toLowerCase().includes(q) ||
        d.actor_identity.toLowerCase().includes(q) ||
        d.mitre_technique.toLowerCase().includes(q) ||
        d.event_name.toLowerCase().includes(q)
      );
    });
  }, [items, search, providerFilter, dispositionFilter]);

  const openCount = items.filter((d) => d.disposition === "open").length;
  const criticalHighCount = items.filter(
    (d) => d.severity === "critical" || d.severity === "high"
  ).length;
  const truePositiveCount = items.filter((d) => d.disposition === "true_positive").length;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="CloudTrail & Azure Activity Log Rules"
        title="Threat Detection"
        description="Deterministic rule detections mapped to MITRE ATT&CK with automatic 30-minute actor event correlation and auditable analyst disposition triage."
      />

      <section aria-label="Detection Summary" className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          label="Total Detections"
          value={items.length}
          subtitle="Ingested rule triggers"
          icon={Activity}
          accent="accent"
        />
        <MetricCard
          label="Open Triage"
          value={openCount}
          subtitle="Awaiting analyst review"
          icon={ShieldAlert}
          accent={openCount > 0 ? "warning" : "success"}
        />
        <MetricCard
          label="Critical & High"
          value={criticalHighCount}
          subtitle="High-impact signals"
          icon={AlertTriangle}
          accent={criticalHighCount > 0 ? "critical" : "success"}
        />
        <MetricCard
          label="Confirmed True Positives"
          value={truePositiveCount}
          subtitle="Validated incidents"
          icon={CheckCircle2}
          accent={truePositiveCount > 0 ? "high" : "neutral"}
        />
      </section>

      {feedback && (
        <div
          role="status"
          className="flex items-center justify-between gap-2 rounded-[12px] border border-[#00D6A0]/35 bg-[#00D6A0]/10 px-4 py-3 text-xs text-[#F1F5F9]"
        >
          <span>{feedback}</span>
          <button
            type="button"
            onClick={() => setFeedback(null)}
            className="text-[#A0AEC0] hover:text-[#F1F5F9]"
          >
            Dismiss
          </button>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2.5 rounded-[12px] border border-[#243142] bg-[#111925] p-3.5">
        <div className="relative flex-1 min-w-[220px]">
          <Search className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5 text-[#64748B]" />
          <input
            placeholder="Search rule ID, actor, event name, MITRE technique..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full rounded-[8px] border border-[#243142] bg-[#080D14] py-2 pl-9 pr-3 text-xs text-[#F1F5F9] placeholder:text-[#64748B] focus:border-[#00D6A0] focus:outline-none"
          />
        </div>
        <select
          aria-label="Filter provider"
          value={providerFilter}
          onChange={(e) => setProviderFilter(e.target.value)}
          className="rounded-[8px] border border-[#243142] bg-[#080D14] px-3 py-2 text-xs text-[#F1F5F9] focus:border-[#00D6A0] focus:outline-none"
        >
          <option value="">All Providers</option>
          <option value="aws">AWS CloudTrail</option>
          <option value="azure">Azure Activity Log</option>
        </select>
        <select
          aria-label="Filter disposition"
          value={dispositionFilter}
          onChange={(e) => setDispositionFilter(e.target.value)}
          className="rounded-[8px] border border-[#243142] bg-[#080D14] px-3 py-2 text-xs text-[#F1F5F9] focus:border-[#00D6A0] focus:outline-none"
        >
          <option value="">All Dispositions</option>
          <option value="open">Open</option>
          <option value="true_positive">True Positive</option>
          <option value="false_positive">False Positive</option>
          <option value="benign">Benign</option>
        </select>
      </div>

      <Panel
        title={`Detection Queue (${filtered.length})`}
        subtitle="Correlated suspicious control-plane activity"
      >
        {query.isPending && <LoadingState label="Loading correlated threat detections..." />}
        {query.isError && <ErrorBanner message={query.error.message} />}
        {query.data && filtered.length === 0 && (
          <EmptyState
            title="No Matching Threat Detections"
            description="No detections match your active filters, or no CloudTrail / Azure Activity Log events have been ingested yet."
          />
        )}
        {query.data && filtered.length > 0 && (
          <div className="space-y-3.5">
            {filtered.map((det) => (
              <div
                key={det.id}
                className="rounded-[12px] border border-[#243142] bg-[#172131]/65 p-4 text-xs space-y-3 transition-colors hover:border-[#2E3F55]"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <ShieldAlert className="h-4 w-4 text-[#F43F5E]" />
                    <span className="font-mono font-semibold text-[#00D6A0]">
                      {det.rule_id}
                    </span>
                    <span className="text-sm font-semibold text-[#F1F5F9]">
                      {det.title}
                    </span>
                    <ProviderBadge provider={det.provider} />
                    <SeverityBadge severity={det.severity} />
                    <StatusBadge status={det.disposition} />
                    <DataSourceBadge source={det.data_source} />
                  </div>
                  <span className="rounded-md border border-[#243142] bg-[#080D14] px-2.5 py-1 font-mono text-[11px] font-medium text-[#F1F5F9]">
                    MITRE {det.mitre_technique} · {det.mitre_tactic}
                  </span>
                </div>

                <p className="leading-relaxed text-[#A0AEC0]">{det.explanation}</p>

                <div className="flex flex-wrap items-center justify-between gap-3 border-t border-[#243142] pt-3 text-[#64748B]">
                  <span className="font-mono text-[11px]">
                    Actor: <span className="text-[#F1F5F9]">{det.actor_identity}</span> · Event:{" "}
                    <span className="text-[#F1F5F9]">{det.event_name}</span> · IP:{" "}
                    <span className="text-[#F1F5F9]">{det.source_ip ?? "n/a"}</span> ·
                    Correlated:{" "}
                    <span className="text-[#00D6A0]">{det.correlated_event_ids.length}</span>
                  </span>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      disabled={disposeMut.isPending || (authQuery.data && !canTriage)}
                      onClick={() =>
                        disposeMut.mutate({ id: det.id, disposition: "true_positive" })
                      }
                      className="rounded-[8px] border border-[#F97316]/35 bg-[#F97316]/12 px-3 py-1.5 text-[11px] font-semibold text-[#F97316] hover:bg-[#F97316]/20 disabled:opacity-45"
                    >
                      Confirm True Positive
                    </button>
                    <button
                      type="button"
                      disabled={disposeMut.isPending || (authQuery.data && !canTriage)}
                      onClick={() =>
                        disposeMut.mutate({ id: det.id, disposition: "false_positive" })
                      }
                      className="rounded-[8px] border border-[#243142] bg-[#0C121B] px-3 py-1.5 text-[11px] font-medium text-[#A0AEC0] hover:text-[#F1F5F9] disabled:opacity-45"
                    >
                      Mark False Positive
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
